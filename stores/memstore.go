package stores

import (
	"context"
	"maps"
	"sync"
	"time"
)

const cleanupPeriod = 100

func NewInMemory() *InMemory {
	return &InMemory{items: make(map[string]memItem)}
}

type InMemory struct {
	lock       sync.RWMutex
	items      map[string]memItem
	updatesNum int
}

func (ms *InMemory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	ms.lock.Lock()
	defer ms.lock.Unlock()
	ms.items[key] = memItem{expire: time.Now().Add(ttl), value: value}
	ms.updatesNum++
	if ms.updatesNum%cleanupPeriod == 0 {
		ms.cleanupExpired()
	}
	return nil
}

func (ms *InMemory) Get(_ context.Context, key string) ([]byte, error) {
	ms.lock.RLock()
	defer ms.lock.RUnlock()
	it, ok := ms.items[key]
	if !ok || time.Now().After(it.expire) {
		return nil, nil
	}
	return it.value, nil
}

func (ms *InMemory) Delete(_ context.Context, key string) error {
	ms.lock.Lock()
	defer ms.lock.Unlock()
	delete(ms.items, key)
	return nil
}

func (ms *InMemory) cleanupExpired() {
	maps.DeleteFunc(ms.items, func(_ string, v memItem) bool {
		return time.Now().After(v.expire)
	})
}

type memItem struct {
	expire time.Time
	value  []byte
}
