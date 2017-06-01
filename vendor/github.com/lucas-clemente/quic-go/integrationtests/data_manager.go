package integrationtests

import (
	"crypto/md5"
	"math/rand"
	"time"
)

type dataManager struct {
	data []byte
	md5  []byte
}

func (m *dataManager) GenerateData(len int) error {
	m.data = make([]byte, len)
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	_, err := r.Read(m.data)
	if err != nil {
		return err
	}
	sum := md5.Sum(m.data)
	m.md5 = sum[:]
	return nil
}

func (m *dataManager) GetData() []byte {
	return m.data
}

func (m *dataManager) GetMD5() []byte {
	return m.md5
}
