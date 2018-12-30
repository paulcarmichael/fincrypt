package cryptop

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"sync"
)

// BERTLVTag struct represents an individual tag
type BERTLVTag struct {
	Tag           string
	Length        string
	MinLength     string
	MaxLength     string
	Value         string
	Name          string
	Format        string
	Valid         bool
	InvalidReason string
}

// EMVDictionary is supported as a singleton containing all EMV tag info
type EMVDictionary struct {
	Tags map[string]BERTLVTag
}

var dictionary *EMVDictionary
var once sync.Once

// GetDictionary returns a populated EMVDictionary
func GetDictionary() *EMVDictionary {
	once.Do(func() {
		dictionary = &EMVDictionary{}

		// open the emvtags.json file
		bytes, err := ioutil.ReadFile("../src/github.com/paulcarmichael/cryptop/emvtags.json")

		if err != nil {
			log.Fatal("Open: ", err)
		}

		// read the file into the EMVDictionary singleton
		err = json.Unmarshal(bytes, dictionary)

		if err != nil {
			log.Fatal("Unmarshal: ", err)
		}

		log.Println("EMV dictionary contains", len(dictionary.Tags), "tags")
	})

	return dictionary
}

// BERTLVParser struct to be populated by the caller
type BERTLVParser struct {
	Request string
}

// Parse is given a string of BERTLV data and returns the parsed tags
func (p BERTLVParser) Parse() (string, error) {
	// pack the request
	data, err := Pack(p.Request)

	if err != nil {
		return "", err
	}

	// parse
	var tags []BERTLVTag

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
			return "", err
		}

		// parse the length, which is one byte
		tag.Length, err = Expand([]byte(data[:1]))

		if err != nil {
			return "", err
		}

		data = data[1:]

		// parse the value, according to the length we just parsed
		valueLength, err := strconv.ParseInt(tag.Length, 16, 16)

		if err != nil {
			return "", err
		}

		// sanity check the given length against the data length
		if valueLength > int64(len(data)) {
			var b strings.Builder

			b.WriteString("ParseBERTLV: Tag ")
			b.WriteString(tag.Tag)
			b.WriteString(" has length ")
			b.WriteString(tag.Length)
			b.WriteString(" but there are only ")
			b.WriteString(strconv.Itoa(len(data)))
			b.WriteString(" bytes remaining")

			return "", errors.New(b.String())
		}

		tag.Value, err = Expand([]byte(data[:valueLength]))

		if err != nil {
			return "", err
		}

		data = data[valueLength:]

		// lookup the tag details in the EMVDictionary
		if dictionaryTag, found := dictionary.Tags[tag.Tag]; found {
			if dictionaryTag.MinLength <= tag.Length &&
				dictionaryTag.MaxLength >= tag.Length {
				tag.Valid = true
			} else {
				var b strings.Builder

				b.WriteString("Tag ")
				b.WriteString(tag.Tag)
				b.WriteString(" has length ")
				b.WriteString(tag.Length)
				b.WriteString(" but the EMV 4.1 specification states it should be minimum ")
				b.WriteString(dictionaryTag.MinLength)
				b.WriteString(" to maximum ")
				b.WriteString(dictionaryTag.MaxLength)

				tag.InvalidReason = b.String()
			}

			tag.Name = dictionaryTag.Name
			tag.Format = dictionaryTag.Format
			tag.MinLength = dictionaryTag.MinLength
			tag.MaxLength = dictionaryTag.MaxLength
		} else {
			var b strings.Builder

			b.WriteString("Tag ")
			b.WriteString(tag.Tag)
			b.WriteString(" is unknown to the EMV 4.1 specification")

			tag.InvalidReason = b.String()
		}

		// add the tag to our slice of parsed tags
		tags = append(tags, tag)
	}

	// convert the slice of parsed tags into json
	result, err := json.Marshal(tags)

	if err != nil {
		return "Failed to convert parsed tags to json", nil
	}

	return string(result), nil
}
