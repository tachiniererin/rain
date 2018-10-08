package torrent

import (
	"strconv"
)

type Status int

const (
	Stopped Status = iota
	Downloading
	Seeding
)

var statusStrings = map[Status]string{
	0: "Stopped",
	1: "Downloading",
	2: "Seeding",
}

func (m Status) String() string {
	s, ok := statusStrings[m]
	if !ok {
		return strconv.FormatInt(int64(m), 10)
	}
	return s
}

// Stats contains statistics about Torrent.
type Stats struct {
	// Status of the torrent.
	Status Status

	// Bytes that are downloaded and passed hash check.
	BytesComplete int64

	// BytesLeft is the number of bytes that is needed to complete all missing pieces.
	BytesIncomplete int64

	// BytesTotal is the number of total bytes of files in torrent.
	//
	// BytesTotal = BytesComplete + BytesIncomplete
	BytesTotal int64

	// BytesDownloaded is the number of bytes downloaded from swarm.
	// Because some pieces may be downloaded more than once, this number may be greater than BytesCompleted returns.
	// BytesDownloaded int64

	// BytesUploaded is the number of bytes uploaded to the swarm.
	// BytesUploaded   int64
}
