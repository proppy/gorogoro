// gorogoro helps lazy gophers to run their programs in the cloud.
// usage:   gorogoro [github.com/import/path]
// TODO:
// - attach stdout
// - target tag firewall
// - wait for exposed port connect
// - reorder flags/cmd
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
	"strings"
	"time"

	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/goauth2/oauth"
	compute "code.google.com/p/google-api-go-client/compute/v1"
	docker "github.com/proppy/go-dockerclient"
)

var (
	project    = flag.String("project", "proppy-containers", "project")
	zone       = flag.String("zone", "us-central1-a", "zone")
	name       = flag.String("name", "gorogoro-vm", "vm name")
	disk       = flag.String("disk", "gorogoro-disk", "disk name")
	image      = flag.String("image", "https://www.googleapis.com/compute/v1/projects/google-containers/global/images/container-vm-v20140522", "vm image")
	api        = flag.String("api", "https://www.googleapis.com/compute/v1", "api url")
	machine    = flag.String("machine", "/zones/us-central1-a/machineTypes/f1-micro", "machine type")
	cred       = flag.String("cred", ".config/gcloud/credentials", "path to gcloud credentials")
	identity   = flag.String("identity", ".ssh/google_compute_engine", "path to gcloud ssh key")
	port       = flag.String("port", "", "container local port")
	from       = flag.String("from", "google/golang-runtime", "docker base image")
	dockerfile = flag.Bool("dockerfile", true, "use package Dockerfile")
	entrypoint = flag.String("entrypoint", "", "entrypoint override")
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

// Dialer is a ssh tunnel connection dialer.
type Dialer func(string, string) (net.Conn, error)

// Tunnel creates a SSH tunnel to a given IP and port.
func (c *Compute) Tunnel(ip string, port int) (Dialer, error) {
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
	return func(net, addr string) (net.Conn, error) {
		parts := strings.Split(addr, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("no port to connect to %q: %v", addr, parts)
		}
		port := parts[1]
		log.Println("tunneling connection to port:", port)
		laddr := fmt.Sprintf("127.0.0.1:%s", parts[1])
		return conn.Dial("tcp", laddr)
	}, nil
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
func NewDocker(dialer Dialer) (*Docker, error) {
	dockerc, err := docker.NewClient("tcp://invalid-hostname:4243")
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}
	dockerc.Client.Transport = &http.Transport{
		Dial: dialer,
	}
	return &Docker{dockerc}, nil
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
		if strings.HasSuffix(path, "Dockerfile") {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to read file info header %q: %v", dir, err)
		}
		header.Name = path[len(dir):]
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

// Command get Entrypoint and Cmd from command line args.
func Command() ([]string, []string) {
	var cmd []string
	if flag.NArg() > 1 {
		cmd = flag.Args()[1:]
	}
	if *entrypoint != "" {
		return []string{*entrypoint}, cmd
	}
	return nil, cmd
}

// Ports get exposed ports from command line args.
func Ports() map[docker.Port]struct{} {
	log.Println("port:", *port)
	if *port != "" {
		return map[docker.Port]struct{}{
			docker.Port(*port): struct{}{},
		}
	}
	return nil
}

// Ports get exposed ports from command line args.
func PortBindings() map[docker.Port][]docker.PortBinding {
	log.Println("port:", *port)
	if *port != "" {
		return map[docker.Port][]docker.PortBinding{
			docker.Port(*port): []docker.PortBinding{},
		}
	}
	return nil
}

// Run create and start a new container based on the given image.
func (d *Docker) Run(name, image string) (*docker.Container, error) {
	command, args := Command()
	ports := Ports()
	log.Printf("running command: %v, args: %v, ports: %v", command, args, ports)
	c, err := d.CreateContainer(
		docker.CreateContainerOptions{
			Name: name,
			Config: &docker.Config{
				Image:        image,
				ExposedPorts: ports,
				Entrypoint:   command,
				Cmd:          args,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create container %q: %v", name, err)
	}
	if err := d.StartContainer(c.ID, &docker.HostConfig{
		PublishAllPorts: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to start container %q: %v", c.ID, err)
	}
	return d.InspectContainer(c.ID)
}

func main() {
	flag.Parse()

	dir, err := ContextDirectory()
	if err != nil {
		log.Printf("failed to infer context directory: %v", err)
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
		log.Fatalf("failed to create root disk", err)
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
	dialer, err := compute.Tunnel(ip, 4243)
	if err != nil {
		log.Fatalf("failed to create ssh tunnel to docker: %v", err)
	}
	dockerc, err := NewDocker(dialer)
	if err != nil {
		log.Fatalf("failed to connect docker to ssh tunnel: %v", err)
	}
	version, err := dockerc.Version()
	if err != nil {
		log.Fatalf("failed to send docker api call: %v", err)
	}
	log.Println("docker version:", version)
	usr, err := user.Current()
	if err != nil {
		log.Fatalf("failed to get current user: %v", err)
	}
	img := usr.Username + "/" + filepath.Base(dir)
	out, err := dockerc.Build(img, context)
	if err != nil {
		log.Fatalf("failed to build docker image %q: %v; %s", img, err, out)
	}
	log.Println("image built:", out)
	cname := fmt.Sprintf("%s-%d", *name, time.Now().Unix())
	container, err := dockerc.Run(cname, img)
	if err != nil {
		log.Fatalf("failed to run container %q: %v", cname, err)
	}
	if len(container.NetworkSettings.Ports) > 0 {
		log.Println("container started with ports:", container.NetworkSettings.Ports)
		for k, bindings := range container.NetworkSettings.Ports {
			for _, p := range bindings {
				log.Println("creating firewall entry for port:", p.HostPort)
				if err := compute.Firewall(cname+"-"+strings.Replace(string(k), "/", "-", -1), p.HostPort); err != nil {
					log.Fatalf("failed to create firewall: %v", err)
				}
				log.Println("firewall entry created for port:", k)
				log.Printf("container port %s available running at: %s", k, ip+":"+p.HostPort)
			}
		}
	}
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
	if *dockerfile == false {
		return fmt.Sprintf("FROM %s\n", *from), nil
	}
	path := filepath.Join(dir, "Dockerfile")
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("no Dockerfile in package %q: %v", path, err)
	}
	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed to read dockerfile %q: %v", path, err)
	}
	return string(bs), nil
}
