package main

import (
	"bbq/client"
	"bbq/crypto"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/alexeyco/simpletable"
	prompt "github.com/c-bata/go-prompt"
	"github.com/kpango/glg"
)

var flagConfigFile = flag.String("config", "/etc/boxbackup/bbackupd.conf", "Main configuration file.")
var flagTlsHost = flag.String("tlshost", "", "Verify remote host certificate against this name.")
var flagVerbose = flag.Bool("verbose", false, "Increase logging output.")

var bb *client.BoxBackup

var nameCache map[int64][]string
var dirCache map[int64][]*client.RemoteFile
var entCache map[int64]*client.RemoteFile
var currentDir int64 = 1

func listDirectory(id int64) ([]*client.RemoteFile, error) {
	if d, ok := dirCache[id]; ok {
		return d, nil
	}
	d, err := bb.ReadDir(id)
	if err != nil {
		return nil, err
	}
	dirCache[id] = d
	for _, e := range d {
		entCache[e.Id] = e
	}
	return d, nil
}

func getHexId(s string) int64 {
	if len(s) > 1 && s[0] == '0' && s[1] == 'x' {
		i, err := strconv.ParseInt(s[2:], 16, 64)
		if err == nil {
			return i
		}
	}
	return 0
}

var suggestions = []prompt.Suggest{
	// Command
	{Text: "exit", Description: "Exit BoxBackup client"},
	{Text: "dir", Description: "List directories"},
	{Text: "ls", Description: "List directories"},
	{Text: "cd", Description: "Change path"},
	{Text: "get", Description: "Get file"},
}

func livePrefix() (string, bool) {
	if currentDir == 1 {
		return ">", true
	}
	n, ok := nameCache[currentDir]
	if !ok {
		d, err := bb.GetObjectName(currentDir, 0)
		if err != nil {
			glg.Errorf("Unable to lookup %v", currentDir)
			return ">", false
		}

		var r []string
		for _, s := range d {
			r = append([]string{s}, r...)
		}
		nameCache[currentDir] = r
		n = r
	}
	return strings.Join(n, "/") + ">", true
}

func printDirectory(args []string) {

	flags := int16(0)
	var pm *regexp.Regexp
	for _, f := range args {
		switch f {
		case "-o":
			flags |= 8 // old
		case "-x":
			flags |= 4 // deleted
		case "-d":
			flags |= 2 // dirs
		case "-f":
			flags |= 1 // files
		default:
			var err error
			if pm, err = regexp.Compile(f); err != nil {
				glg.Errorf("Error compiling '%s' pattern: %s", f, err)
				pm = nil
			}
		}
	}
	if flags == 0 {
		flags = 2 + 1
	}

	table := simpletable.New()

	table.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: "ID"},
			{Align: simpletable.AlignCenter, Text: "Name"},
			{Align: simpletable.AlignCenter, Text: "Modified"},
			{Align: simpletable.AlignCenter, Text: "Mode"},
			{Align: simpletable.AlignCenter, Text: "Flags"},
			{Align: simpletable.AlignCenter, Text: "Size"},
		},
	}
	var t int64

	de, err := listDirectory(currentDir)
	if err != nil {
		fmt.Printf("Can not get current directory: %s\n", err)
		return
	}

	for _, e := range de {
		if e.Flags&flags == 0 || (pm != nil && pm.FindString(e.Name()) == "") {
			continue
		}
		r := []*simpletable.Cell{
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%x", e.Id)},
			{Text: e.Name()},
			{Text: e.ModificationTime.String()},
			{Align: simpletable.AlignRight, Text: e.Mode().String()},
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%b", e.Flags)},
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", e.Size())},
		}
		table.Body.Cells = append(table.Body.Cells, r)
		t += e.Size()
	}
	table.Footer = &simpletable.Footer{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%x", currentDir)},
			{Text: "."},
			{Text: ""},
			{Text: ""},
			{Align: simpletable.AlignRight, Text: "Total"},
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", t)},
		},
	}
	table.SetStyle(simpletable.StyleRounded)
	fmt.Println(table.String())
}

func executor(in string) {
	in = strings.TrimSpace(in)
	blocks := strings.Split(in, " ")

	de, err := listDirectory(currentDir)
	if err != nil {
		fmt.Printf("Can not get current directory: %s\n", err)
		return
	}

	switch blocks[0] {
	case "exit", "quit":
		fmt.Println("Bye!")
		bb.Finish()
		os.Exit(0)

	case "connect":

	case "get":
		if len(blocks) > 1 {
			n := blocks[1]
			f := getHexId(n)
			if f == 0 {
				for _, e := range de {
					if !e.IsDir() && e.Name() == n {
						f = e.Id
					}
				}
			}
			if f > 0 {
				rf, err := bb.OpenFile(currentDir, f)
				if err != nil {
					glg.Errorf("opening file: %q", err)
					return
				}
				defer rf.Close()

				c := []string{"-c", "less"}
				if len(blocks) > 2 && blocks[2][0] == '|' {
					c = []string{"-c", strings.Join(blocks[2:], " ")[1:]}
				}
				cmd := exec.Command("/bin/sh", c...)
				cmd.Stdin = rf
				cmd.Stdout = os.Stdout
				if err = cmd.Run(); err != nil {
					glg.Printf("Command '%v' finished with error: %v", c, err)
				}
			}
		}
		return

	case "v", "ls", "dir":
		printDirectory(blocks[1:])
		return

	case "c", "cd":
		if len(blocks) < 2 || blocks[1] == ".." {
			if currentDir > 1 {
				if c, ok := entCache[currentDir]; ok {
					currentDir = c.ParentId
				}
			}
			return
		}
		if blocks[1] == "/" {
			currentDir = 1
			return
		}

		n := strings.Join(blocks[1:], " ")
		var ch int64
		if ch = getHexId(n); ch == 0 {
			for _, e := range de {
				if (e.Flags&2) != 0 && e.Name() == n {
					ch = e.Id
				}
			}
		}
		if ch > 0 {
			currentDir = ch
		}
		return
	}

	fmt.Println("Sorry, I don't understand.")
}

func completer(in prompt.Document) []prompt.Suggest {
	blocks := strings.Split(strings.TrimSpace(in.CurrentLine()), " ")
	w := in.GetWordBeforeCursor()

	if len(blocks) > 1 && w == "" && (len(blocks) < 3 || blocks[2][0] != '|') {
		return []prompt.Suggest{}
	}

	var s []prompt.Suggest
	de, err := listDirectory(currentDir)
	if err != nil {
		glg.Error(err)
		return nil
	}
	numeric := false
	if len(w) > 0 && w[0] == byte('0') {
		numeric = true
	}

	for _, e := range de {
		switch blocks[0] {
		case "get":
			if e.IsDir() {
				continue
			}
			if len(blocks) > 2 && blocks[2][0] == '|' {
				return []prompt.Suggest{
					{Text: "| foo", Description: "Pipe the data through foo command."},
				}
			}

		case "cd":
			if !e.IsDir() {
				continue
			}
		default:
			if w == "" {
				return []prompt.Suggest{}
			}
			return prompt.FilterHasPrefix(suggestions, w, true)
		}

		if numeric {
			s = append(s, prompt.Suggest{
				Text:        fmt.Sprintf("0x%x", e.Id),
				Description: e.Name(),
			})
		} else {
			s = append(s, prompt.Suggest{
				Text:        e.Name(),
				Description: fmt.Sprintf("0x%x", e.Id),
			})
		}
	}
	return prompt.FilterHasPrefix(s, w, true)
}

func main() {
	flag.Parse()

	cfg, err := client.NewConfig(*flagConfigFile)
	if err != nil {
		glg.Error(err)
		return
	}

	if *flagVerbose {
		glg.Info("Increased verbosity")
	} else {
		glg.Get().SetLevelMode(glg.DEBG, glg.NONE)
		glg.Get().SetLevelMode(glg.INFO, glg.NONE)
	}

	cr, err := crypto.NewCrypto(cfg.Strings["KeysFile"])
	if err != nil {
		glg.Error(err)
		return
	}

	s, err := crypto.NewStoreConnection(
		*flagTlsHost,
		cfg.Strings["TrustedCAsFile"],
		cfg.Strings["CertificateFile"],
		cfg.Strings["PrivateKeyFile"],
	)
	if err != nil {
		glg.Error(err)
	}
	c, err := s.Connect(cfg.Strings["StoreHostname"])
	if err != nil {
		glg.Error(err)
		return
	}
	defer c.Close()

	bb = client.NewBoxBackup(c, cr)
	defer bb.Finish()

	if err := bb.CheckVersion(1); err != nil {
		glg.Error(err)
		return
	}

	if err := bb.Login(1, true); err != nil {
		glg.Error(err)
		return
	}

	dirCache = make(map[int64][]*client.RemoteFile)
	entCache = make(map[int64]*client.RemoteFile)
	nameCache = make(map[int64][]string)

	executor("ls")
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("> "),
		prompt.OptionLivePrefix(livePrefix),
		prompt.OptionPrefixTextColor(prompt.Yellow),
		prompt.OptionTitle("BoxBackup"),
	)
	p.Run()
}
