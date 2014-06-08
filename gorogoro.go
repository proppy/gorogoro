package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path"
	"time"

	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/goauth2/oauth"
	compute "code.google.com/p/google-api-go-client/compute/v1"
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
)

var credentials Credentials
var key Key

// Credentials store gcloud credentials.
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
		return "", fmt.Errorf("enable to get current user")
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
		return fmt.Errorf("unable to load credentials from %q: %v", path, err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(c); err != nil {
		return fmt.Errorf("enable to decode credentials: %v", err)
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
	prefix := *api + "/projects/" + c.Project
	op, err := c.Instances.Insert(c.Project, c.Zone, &compute.Instance{
		Name:        name,
		Description: "gorogoro vm",
		MachineType: prefix + *machine,
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
				Network: prefix + "/global/networks/default",
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

func (c *Compute) wait(op *compute.Operation) error {
	for {
		op, err := c.ZoneOperations.Get(c.Project, c.Zone, op.Name).Do()
		log.Printf("operation %q status: %s, %v", op.Name, op.Status, err)
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

type Key struct {
	ssh.Signer
}

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

func (k *Key) path() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("enable to get current user")
	}
	return path.Join(usr.HomeDir, *identity), nil
}

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

func main() {
	if err := credentials.Read(); err != nil {
		log.Fatalf("failed to read credentials: %v", err)
	}
	transport, err := credentials.Transport()
	if err != nil {
		log.Fatalf("failed to create transport: %v", err)
	}
	compute, err := NewCompute(transport.Client())
	if err != nil {
		log.Fatalf("failed to create compute: %v", err)
	}
	diskUrl, err := compute.Disk(*disk)
	if err != nil {
		log.Fatalf("error creating root disk")
	}
	log.Println("disk url:", diskUrl)
	instanceUrl, err := compute.Instance(*name, diskUrl)
	if err != nil {
		log.Fatalf("error creating instance", err)
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
	fmt.Println(conn, err)
}
