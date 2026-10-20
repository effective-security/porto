package cache_test

import (
	"context"
	"fmt"
	"time"

	"github.com/effective-security/porto/pkg/cache"
)

func ExampleProvider_listKeys() {
	ctx := context.Background()
	p := cache.NewMemoryProvider("/myapp")
	for _, key := range []string{"user/1", "user/2", "user/3", "order/1"} {
		if err := p.Set(ctx, key, "v", time.Minute); err != nil {
			panic(err)
		}
	}

	// start with an empty cursor and stop when the returned one is empty;
	// a Redis page may be empty, or repeat a key, before the end
	cursor := ""
	for {
		keys, next, err := p.ListKeys(ctx, "user/*", cursor, 2)
		if err != nil {
			panic(err)
		}
		for _, key := range keys {
			fmt.Println(key)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	// Output:
	// user/1
	// user/2
	// user/3
}
