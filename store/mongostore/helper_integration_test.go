//go:build integration

package mongostore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/devXpro/mcp-gatekeeper/store"
	"github.com/devXpro/mcp-gatekeeper/store/mongostore"
)

// mongoURI is the throwaway replica set every test of the package shares; each test gets its own database.
var mongoURI string

// TestMain starts one mongo:8.0 container as a single-node replica set rs0, runs the tests, and removes the
// container whatever happens.
func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mongostore integration setup:", err)
		code = 1
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := "gk-g1-mongo-" + hex.EncodeToString(suffix)

	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::27017", //nolint:gosec // test helper, the name is generated here
		"mongo:8.0", "--replSet", "rs0", "--bind_ip", "0.0.0.0").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("docker run: %w: %s", err, out)
	}
	defer func() { _ = exec.Command("docker", "rm", "-f", name).Run() }() //nolint:gosec // test helper

	out, err = exec.Command("docker", "port", name, "27017/tcp").Output() //nolint:gosec // test helper
	if err != nil {
		return 0, fmt.Errorf("docker port: %w", err)
	}
	addr := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]) // "127.0.0.1:49153"
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		return 0, fmt.Errorf("unexpected docker port output %q", out)
	}
	mongoURI = "mongodb://" + addr + "/?directConnection=true"

	if err := initiateReplicaSet(mongoURI); err != nil {
		return 0, err
	}
	return m.Run(), nil
}

// initiateReplicaSet waits for mongod, runs replSetInitiate and waits for the primary.
func initiateReplicaSet(uri string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(2 * time.Second))
	if err != nil {
		return err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	admin := client.Database("admin")
	cfg := bson.D{{Key: "replSetInitiate", Value: bson.D{
		{Key: "_id", Value: "rs0"},
		{Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: "localhost:27017"}}}},
	}}}
	var lastErr error
	for ctx.Err() == nil {
		lastErr = admin.RunCommand(ctx, cfg).Err()
		if lastErr == nil || strings.Contains(lastErr.Error(), "already initialized") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("replSetInitiate: %w", lastErr)
	}
	for ctx.Err() == nil {
		var res struct {
			Primary bool `bson:"isWritablePrimary"`
		}
		if err := admin.RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&res); err == nil && res.Primary {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("the replica set never got a primary: %w", ctx.Err())
}

// newStore opens a Store on a fresh database, with cascades, and drops the database when the test ends.
func newStore(t *testing.T, cascades ...store.Cascade) *mongostore.Store {
	t.Helper()
	s, _ := newStoreDB(t, cascades...)
	return s
}

// newStoreDB is newStore that also returns the database name.
func newStoreDB(t *testing.T, cascades ...store.Cascade) (*mongostore.Store, string) {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	dbName := "t_" + hex.EncodeToString(b)
	s, err := mongostore.Open(context.Background(), mongostore.Options{URI: mongoURI, Database: dbName, Cascades: cascades})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
		if err == nil {
			_ = client.Database(dbName).Drop(context.Background())
			_ = client.Disconnect(context.Background())
		}
	})
	return s, dbName
}

// rawDB returns the database dbName through a client of its own, for looking at documents as they are stored.
func rawDB(t *testing.T, dbName string) *mongo.Database {
	t.Helper()
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client.Database(dbName)
}
