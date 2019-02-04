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
	Length        int64
	MinLength     int64
	MaxLength     int64
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
		bytes, err := ioutil.ReadFile("/go/src/github.com/paulcarmichael/cryptop/emvtags.json")

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
	Input string
}

// Calculate is given a string of BERTLV data and returns the parsed tags
func (p BERTLVParser) Calculate() (string, error) {
	// pack the request
	data, err := Pack(p.Input, InputNameInput)

	if err != nil {
		return "", err
	}

	// parse
	var tags []BERTLVTag

ParseLoop:
	for len(data) != 0 {

		var tag BERTLVTag

		// parse the tag, which can be multiple bytes long, identified by the last 5 bytes being set
		for {
			// for the case of multibyte tags, sanity check there is some remaining data to operate on
			if len(data) == 0 {
				tag.InvalidReason = string("Not enough data remaining to parse tag")
				tag.Tag, _ = Expand([]byte(tag.Tag))
				tags = append(tags, tag)

				break ParseLoop
			}

			tag.Tag += data[:1]

			if data[0]&0x1F == 0x1F {
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

		// lookup the tag in the dictionary
		if dictionaryTag, found := GetDictionary().Tags[tag.Tag]; found {

			// save the dictionary details into the current tag
			tag.Name = dictionaryTag.Name
			tag.Format = dictionaryTag.Format
			tag.MinLength = dictionaryTag.MinLength
			tag.MaxLength = dictionaryTag.MaxLength
		} else {
			var b strings.Builder

			b.WriteString("Tag ")
			b.WriteString(tag.Tag)
			b.WriteString(" is unknown to the EMV 4.3 specification")

			tag.InvalidReason = b.String()
		}

		// sanity check there is some remaining data to operate on
		if len(data) == 0 {
			tag.InvalidReason = string("Not enough data remaining to parse tag length")
			tags = append(tags, tag)

			break ParseLoop
		}

		// parse the length, which is one byte
		sLength, err := Expand([]byte(data[:1]))

		if err != nil {
			return "", err
		}

		tag.Length, err = strconv.ParseInt(sLength, 16, 16)

		if err != nil {
			return "", err
		}

		data = data[1:]

		// sanity check the given length against the data length
		if tag.Length > int64(len(data)) {
			var b strings.Builder

			b.WriteString("Tag ")
			b.WriteString(tag.Tag)
			b.WriteString(" has length ")
			b.WriteString(strconv.FormatInt(tag.Length, 10))
			b.WriteString(" but there are only ")
			b.WriteString(strconv.FormatInt(int64(len(data)), 10))
			b.WriteString(" bytes remaining")

			tag.InvalidReason = b.String()
			tag.Value, _ = Expand([]byte(data[0:]))

			tags = append(tags, tag)

			break ParseLoop
		}

		// parse the value, given be tag length
		tag.Value, err = Expand([]byte(data[:tag.Length]))

		if err != nil {
			return "", err
		}

		data = data[tag.Length:]

		// validate the tag using the dictionary details
		if dictionaryTag, found := GetDictionary().Tags[tag.Tag]; found {
			if dictionaryTag.MinLength <= tag.Length &&
				dictionaryTag.MaxLength >= tag.Length {
				tag.Valid = true
			} else {
				var b strings.Builder

				b.WriteString("Tag ")
				b.WriteString(tag.Tag)
				b.WriteString(" has length ")
				b.WriteString(strconv.FormatInt(tag.Length, 10))
				b.WriteString(", the EMV 4.3 specification states this length should be minimum ")
				b.WriteString(strconv.FormatInt(dictionaryTag.MinLength, 10))
				b.WriteString(" to maximum ")
				b.WriteString(strconv.FormatInt(dictionaryTag.MaxLength, 10))

				tag.InvalidReason = b.String()
			}
		}

		// add the tag to our slice of parsed tags
		tags = append(tags, tag)
	}

	// convert the slice of parsed tags into json
	result, err := json.Marshal(tags)

	if err != nil {
		return "", errors.New("Failed to convert parsed tags to json")
	}

	return string(result), nil
}
