package cryptop

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strconv"
	"sync"
)

// BERTLVTag struct represents an individual tag
type BERTLVTag struct {
	Tag       string
	Length    string // used for parsing
	MinLength string // used for tag definitions
	MaxLength string // used for tag definitions
	Value     string
	Name      string
	Format    string
}

// EMVDictionary is supported as a singleton containing all EMV tag info
type EMVDictionary struct {
	Tags []BERTLVTag
}

var singleton *EMVDictionary
var once sync.Once

// GetDictionary returns a populated EMVDictionary
func GetDictionary() *EMVDictionary {
	once.Do(func() {
		singleton = &EMVDictionary{}

		// open the emvtags.json file
		bytes, err := ioutil.ReadFile("../src/github.com/paulcarmichael/cryptop/emvtags.json")

		if err != nil {
			log.Fatal("Open: ", err)
		}

		// read the file into the EMVDictionary singleton
		err = json.Unmarshal(bytes, singleton)

		if err != nil {
			log.Fatal("Unmarshal: ", err)
		}

		// check the contents
		for _, tag := range singleton.Tags {
			log.Println("Read EMV tag", tag.Tag)
		}

		log.Println("EMV dictionary contains", len(singleton.Tags), "tags")
	})

	return singleton
}

// ParseBERTLV is given a string of BERTLV data and returns the parsed tags
func ParseBERTLV(data string) ([]BERTLVTag, error) {
	data = "9F1008AAAAAAAAAAAAAAAA9004BBCC"

	var tags []BERTLVTag

	// pack the data
	data, err := Pack(data)

	if err != nil {
		return tags, err
	}

	// parse
	for len(data) != 0 {
		var tag BERTLVTag

		// parse the tag, which can be multiple bytes long, identified by the presence of bit 4
		for {
			tag.Tag += data[:1]

			if data[0]&0x08 == 0x08 {
				data = data[1:]
			} else {
				data = data[1:]
				break
			}
		}

		tag.Tag, err = Expand([]byte(tag.Tag))

		if err != nil {
			return tags, err
		}

		// parse the length, which is one byte
		tag.Length, err = Expand([]byte(data[:1]))

		if err != nil {
			return tags, err
		}

		data = data[1:]

		// parse the value, according to the length we just parsed
		valueLength, err := strconv.ParseInt(tag.Length, 16, 16)

		if err != nil {
			return tags, err
		}

		tag.Value, err = Expand([]byte(data[:valueLength]))

		if err != nil {
			return tags, err
		}

		// sanity check the given length against the data length
		if valueLength > int64(len(data)) {
			// exit!
		}

		data = data[valueLength:]

		// add the tag to our slice of parsed tags
		tags = append(tags, tag)
	}

	return tags, nil
}
