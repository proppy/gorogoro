package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"time"

	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/goauth2/oauth"
	compute "code.google.com/p/google-api-go-client/compute/v1"
	"github.com/proppy/go-dockerclient"
)

var (
	project  = flag.String("project", "proppy-containers", "project")
	zone     = flag.String("zone", "us-central1-a", "zone")
	name     = flag.String("name", "gorogoro-vm", "vm name")
	disk     = flag.String("disk", "gorogoro-disk", "disk name")
	image    = flag.String("image", "https://www.googleapis.com/compute/v1/projects/google-containers/global/images/container-vm-v20140522", "vm image")
	api      = flag.String("api", "https://www.googleapis.com/compute/v1", "api url")
	machine  = flag.String("machine", "/zones/us-central1-a/machineTypes/f1-micro", "machine type")
	cred     = flag.String("cred", ".config/gcloud/credentials", "path to gcloud credentials")
	identity = flag.String("identity", ".ssh/google_compute_engine", "path to gcloud ssh key")
	port     = flag.String("port", "8080/tcp", "container local port")
	from     = flag.String("from", "google/golang-runtime", "docker base image")
)

const (
	usage = "usage: gorogoro [go/pkg/path]"
)

var credentials Credentials
var key Key

// Credentials stores gcloud credentials.
type Credentials struct {
	Data []struct {
		Credential struct {
			ClientId     string `json:"Client_Id"`
			ClientSecret string `json:"Client_Secret"`
			RefreshToken string `json:"Refresh_Token"`
		}
		Key struct {
			Scope string
		}
		ProjectId string `json:"projectId"`
	}
}

// Path returns gcloud credentials path.
func (c *Credentials) path() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user")
	}
	return path.Join(usr.HomeDir, *cred), nil
}

// Read reads the credentials from disk.
func (c *Credentials) Read() error {
	path, err := c.path()
	if err != nil {
		return fmt.Errorf("failed to get credentials path: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to load credentials from %q: %v", path, err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(c); err != nil {
		return fmt.Errorf("failed to decode credentials: %v", err)
	}
	if len(c.Data) == 0 {
		return fmt.Errorf("no credentials in: %q", path)
	}
	return nil
}

// Transport return a oauth2.Transport for the gcloud credentials.
func (c *Credentials) Transport() (*oauth.Transport, error) {
	t := &oauth.Transport{
		Config: &oauth.Config{
			ClientId:     c.Data[0].Credential.ClientId,
			ClientSecret: c.Data[0].Credential.ClientSecret,
			Scope:        c.Data[0].Key.Scope,
			RedirectURL:  "oob",
			AuthURL:      "https://accounts.google.com/o/oauth2/auth",
			TokenURL:     "https://accounts.google.com/o/oauth2/token",
			AccessType:   "offline",
		},
		Token:     &oauth.Token{RefreshToken: c.Data[0].Credential.RefreshToken},
		Transport: http.DefaultTransport,
	}
	err := t.Refresh()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %v", err)
	}
	return t, nil
}

// Compute is a Google Compute Engine services associated to a given project and zone.
type Compute struct {
	*compute.Service
	Project string
	Zone    string
	Prefix  string
}

// NewCompute returns a new Compute service.
func NewCompute(client *http.Client) (*Compute, error) {
	service, err := compute.New(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %v", err)
	}
	return &Compute{
		service,
		*project,
		*zone,
		*api + "/projects/" + *project,
	}, nil
}

// Disk gets or creates a new root disk.
func (c *Compute) Disk(name string) (string, error) {
	disk, err := c.Disks.Get(c.Project, c.Zone, name).Do()
	if err == nil {
		log.Printf("found existing root disk: %q", disk.SelfLink)
		return disk.SelfLink, nil
	}
	log.Printf("not found, creating new root disk: %q", name)
	op, err := c.Disks.Insert(c.Project, c.Zone, &compute.Disk{
		Name: name,
	}).SourceImage(*image).Do()
	if err != nil {
		return "", fmt.Errorf("disk insert api call failed: %v", err)
	}
	if err := c.wait(op); err != nil {
		return "", fmt.Errorf("disk insert operation failed: %v", err)
	}
	log.Printf("root disk created: %q", op.TargetLink)
	return op.TargetLink, nil
}

// Instance gets or creates a new instance.
func (c *Compute) Instance(name, disk string) (string, error) {
	instance, err := c.Instances.Get(c.Project, c.Zone, name).Do()
	if err == nil {
		log.Printf("found existing instance: %q", instance.SelfLink)
		return instance.SelfLink, nil
	}
	log.Printf("not found, creating new instance: %q", name)
	op, err := c.Instances.Insert(c.Project, c.Zone, &compute.Instance{
		Name:        name,
		Description: "gorogoro vm",
		MachineType: c.Prefix + *machine,
		Disks: []*compute.AttachedDisk{
			{
				Boot:   true,
				Type:   "PERSISTENT",
				Mode:   "READ_WRITE",
				Source: disk,
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: []*compute.AccessConfig{
					&compute.AccessConfig{Type: "ONE_TO_ONE_NAT"},
				},
				Network: c.Prefix + "/global/networks/default",
			},
		},
	}).Do()
	if err != nil {
		return "", fmt.Errorf("instance insert api call failed: %v", err)
	}
	if err := c.wait(op); err != nil {
		return "", fmt.Errorf("instance insert operation failed: %v", err)
	}
	log.Printf("instance created: %q", op.TargetLink)
	return op.TargetLink, nil
}

// WaitConnection waits until a connection a instance on a given port is successful.
func (c *Compute) WaitConnection(name string, port int) (string, error) {
	for {
		instance, err := c.Instances.Get(c.Project, c.Zone, name).Do()
		if err != nil {
			return "", fmt.Errorf("could not find instance %q: %v", name, err)
		}

		if ip := instance.NetworkInterfaces[0].AccessConfigs[0].NatIP; ip != "" {
			addr := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Println("connection to %q failed: %v", addr, err)
				continue
			}
			defer conn.Close()
			log.Printf("connection to %q succeeded", addr)
			return ip, nil
		}
		time.Sleep(1 * time.Second)
	}
}

// wait waits for an zone operations to be DONE.
func (c *Compute) wait(operation *compute.Operation) error {
	for {
		op, err := c.ZoneOperations.Get(c.Project, c.Zone, operation.Name).Do()
		if err != nil {
			return fmt.Errorf("failed to get operation: %v", operation.Name, err)
		}
		log.Printf("operation %q status: %s", operation.Name, op.Status)
		if op.Status == "DONE" {
			if op.Error != nil {
				return fmt.Errorf("operation error: %v", *op.Error.Errors[0])
			}
			break
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// waitGlobal waits for an zone operations to be DONE.
func (c *Compute) waitGlobal(operation *compute.Operation) error {
	for {
		op, err := c.GlobalOperations.Get(c.Project, operation.Name).Do()
		if err != nil {
			return fmt.Errorf("failed to get operation: %v", operation.Name, err)
		}
		log.Printf("operation %q status: %s", operation.Name, op.Status)
		if op.Status == "DONE" {
			if op.Error != nil {
				return fmt.Errorf("operation error: %v", *op.Error.Errors[0])
			}
			break
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// Key is a type for a SSH private key.
type Key struct {
	ssh.Signer
}

// Read parses a private SSH key.
func (k *Key) Read() error {
	path, err := k.path()
	if err != nil {
		return fmt.Errorf("failed to get ssh key path: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to load ssh key from %q: %v", path, err)
	}
	defer f.Close()

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read ssh key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(bs)
	if err != nil {
		return fmt.Errorf("failed to parse ssh key: %v", err)
	}
	k.Signer = signer
	return nil
}

// path returns the path to the gcloud SSH key.
func (k *Key) path() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user")
	}
	return path.Join(usr.HomeDir, *identity), nil
}

// Tunnel creates a SSH tunnel to a given IP and port.
func (c *Compute) Tunnel(ip string, port int) (net.Conn, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %v", err)
	}
	if err := key.Read(); err != nil {
		return nil, fmt.Errorf("failed to read ssh private key: %v", err)
	}
	raddr := ip + ":22"
	conn, err := ssh.Dial("tcp", ip+":22", &ssh.ClientConfig{
		User: usr.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial ssh conn to %q: %v", raddr, err)
	}
	laddr := fmt.Sprintf("127.0.0.1:%d", port)
	return conn.Dial("tcp", laddr)
}

// Firewall creates a firewall for a given port.
func (c *Compute) Firewall(name, port string) error {
	op, err := c.Firewalls.Insert(c.Project, &compute.Firewall{
		Name:         name,
		Network:      c.Prefix + "/global/networks/default",
		SourceRanges: []string{"0.0.0.0/0"},
		Allowed: []*compute.FirewallAllowed{&compute.FirewallAllowed{
			IPProtocol: "tcp",
			Ports:      []string{port},
		}},
	}).Do()
	if err != nil {
		return fmt.Errorf("insert firewall api called failed: %v", err)
	}
	return c.waitGlobal(op)
}

// Docker is a docker client.
type Docker struct {
	*docker.Client
}

// NewDocker returns a new docker client using the given net.Conn.
func NewDocker(conn net.Conn) (*Docker, error) {
	docker, err := docker.NewClient("tcp://invalid-hostname:4243")
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}
	docker.Client.Transport = &http.Transport{
		Dial: func(proto string, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	return &Docker{docker}, nil
}

// NewContext returns a new docker build context w/ the given Dockerfile and directory.
func NewContext(dockerfile, dir string) (io.Reader, error) {
	var context bytes.Buffer
	tr := tar.NewWriter(&context)
	defer tr.Close()
	tr.WriteHeader(&tar.Header{Name: "Dockerfile", Size: int64(len(dockerfile))})
	tr.Write([]byte(dockerfile))
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk directory %q: %v", dir, err)
		}
		if info.IsDir() {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to read file info header %q: %v", dir, err)
		}
		tr.WriteHeader(header)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open %q: %v", path, err)
		}
		defer f.Close()
		n, err := io.Copy(tr, f)
		if err != nil {
			return fmt.Errorf("failed to archive file %q: %v", path, err)
		}
		log.Printf("archived path %q (%d bytes)", path, n)
		return nil
	})
	return &context, err
}

// Build builds the given context into a docker image.
func (d *Docker) Build(image string, context io.Reader) (string, error) {
	var output bytes.Buffer
	log.Printf("building image: %q", image)
	err := d.BuildImage(docker.BuildImageOptions{
		Name:         image,
		InputStream:  context,
		OutputStream: &output,
	})
	return output.String(), err
}

// Run create and start a new container based on the given image.
func (d *Docker) Run(name, image string) (string, error) {
	c, err := d.CreateContainer(
		docker.CreateContainerOptions{
			Name: name,
			Config: &docker.Config{
				Image: image,
			},
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create container %q: %v", name, err)
	}
	if err := d.StartContainer(c.ID, &docker.HostConfig{PublishAllPorts: true}); err != nil {
		return "", fmt.Errorf("failed to start container %q: %v", c.ID, err)
	}
	c, err = d.InspectContainer(c.ID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %q: %v", c.ID, err)
	}
	return c.NetworkSettings.Ports[docker.Port(*port)][0].HostPort, nil
}

func main() {
	flag.Parse()

	dir, err := ContextDirectory()
	if err != nil {
		log.Printf("failed to get context directory: %v", err)
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(-1)
	}
	log.Println("context:", dir)

	dockerfile, err := Dockerfile(dir)
	if err != nil {
		log.Printf("failed to infer Dockerfile: %v", err)
	}
	log.Println("dockerfile:", dockerfile)

	context, err := NewContext(dockerfile, dir)
	if err != nil {
		log.Fatalf("failed to create context: %v", err)
	}

	if err := credentials.Read(); err != nil {
		log.Fatalf("failed to read credentials: %v", err)
	}
	transport, err := credentials.Transport()
	if err != nil {
		log.Fatalf("failed to create transport: %v", err)
	}
	compute, err := NewCompute(transport.Client())
	if err != nil {
		log.Fatalf("failed to create compute client: %v", err)
	}
	diskUrl, err := compute.Disk(*disk)
	if err != nil {
		log.Fatalf("failed to create root disk")
	}
	log.Println("disk url:", diskUrl)
	instanceUrl, err := compute.Instance(*name, diskUrl)
	if err != nil {
		log.Fatalf("failed to create instance", err)
	}
	log.Println("instance url:", instanceUrl)
	ip, err := compute.WaitConnection(*name, 22)
	if err != nil {
		log.Fatalf("failed to connect to instance ssh port: %v", err)
	}
	log.Println("instance ip:", ip)
	conn, err := compute.Tunnel(ip, 4243)
	if err != nil {
		log.Fatalf("failed to create ssh tunnel to docker: %v", err)
	}
	log.Println(conn)
	docker, err := NewDocker(conn)
	if err != nil {
		log.Fatalf("failed to connect docker to ssh tunnel: %v", err)
	}
	version, err := docker.Version()
	if err != nil {
		log.Fatalf("failed to send docker api call: %v", err)
	}
	log.Println("docker version:", version)
	usr, err := user.Current()
	if err != nil {
		log.Fatalf("failed to get current user: %v", err)
	}
	img := usr.Username + "/" + filepath.Base(dir)
	out, err := docker.Build(img, context)
	if err != nil {
		log.Fatalf("failed to build docker image %q: %v; %s", img, err, out)
	}
	log.Println("image built:", out)
	ctr := fmt.Sprintf("%s-%d", *name, time.Now().Unix())
	port, err := docker.Run(ctr, img)
	log.Println("container started on port:", port)
	if err := compute.Firewall(ctr+"-firewall", port); err != nil {
		log.Fatalf("failed to create firewall: %v", err)
	}
	log.Println("firewall entry created for port:", port)
	fmt.Println("container running:", ip+":"+port)
}

func ContextDirectory() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}
	if flag.NArg() == 0 {
		return cwd, nil
	}
	pkg := flag.Arg(0)
	gopath := filepath.Join(os.Getenv("GOPATH"), "src")
	paths := []string{
		cwd,
		gopath,
	}
	for _, p := range paths {
		path := filepath.Join(p, filepath.Clean(pkg))
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			continue
		}
		return filepath.Abs(path)
	}
	if output, err := exec.Command("go", "get", pkg).CombinedOutput(); err != nil {
		return "", fmt.Errorf("no such go package %q: %v; %s", pkg, err, output)
	}
	return filepath.Join(gopath, pkg), nil
}

func Dockerfile(dir string) (string, error) {
	path := filepath.Join(dir, "Dockerfile")
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("FROM %s\n", *from), nil
	}
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed to read docker %q: %v", path, err)
	}
	return string(bs), nil
}
