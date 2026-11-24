package mongostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/devXpro/mcp-gatekeeper/core"
)

// col is a collection with the store's error mapping. Every call runs in the transaction the context carries, if
// any: the driver takes the session from the context.
type col struct {
	c *mongo.Collection
}

// c returns the collection name.
func (s *Store) c(name string) col { return col{c: s.db.Collection(name)} }

func (c col) name() string { return c.c.Name() }

func (c col) wrap(op string, err error) error {
	return fmt.Errorf("mongostore: %s %s: %w", c.name(), op, err)
}

// notFound is the error for a missing entity of this collection.
func (c col) notFound(op string) error {
	return c.wrap(op, core.ErrNotFound)
}

// insert adds a document; an existing _id or unique key is core.ErrConflict.
func (c col) insert(ctx context.Context, doc any) error {
	if _, err := c.c.InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return c.wrap("insert", core.ErrConflict)
		}
		return c.wrap("insert", err)
	}
	return nil
}

// upsert inserts doc or replaces the document with the same _id.
func (c col) upsert(ctx context.Context, id, doc any) error {
	_, err := c.c.ReplaceOne(ctx, idIs(id), doc, options.Replace().SetUpsert(true))
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return c.wrap("put", core.ErrConflict)
		}
		return c.wrap("put", err)
	}
	return nil
}

// update applies an update to the one document matching filter; no match is core.ErrNotFound.
func (c col) update(ctx context.Context, filter, update any) error {
	res, err := c.c.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.wrap("update", err)
	}
	if res.MatchedCount == 0 {
		return c.notFound("update")
	}
	return nil
}

// updateMany applies update to every document matching filter; matching none is fine.
func (c col) updateMany(ctx context.Context, filter, update any) error {
	if _, err := c.c.UpdateMany(ctx, filter, update); err != nil {
		return c.wrap("update many", err)
	}
	return nil
}

// deleteOne deletes the one document matching filter; no match is core.ErrNotFound.
func (c col) deleteOne(ctx context.Context, filter any) error {
	res, err := c.c.DeleteOne(ctx, filter)
	if err != nil {
		return c.wrap("delete", err)
	}
	if res.DeletedCount == 0 {
		return c.notFound("delete")
	}
	return nil
}

// deleteMany deletes every document matching filter and returns how many it removed.
func (c col) deleteMany(ctx context.Context, filter any) (int, error) {
	res, err := c.c.DeleteMany(ctx, filter)
	if err != nil {
		return 0, c.wrap("delete many", err)
	}
	return int(res.DeletedCount), nil
}

// count returns the number of documents matching filter.
func (c col) count(ctx context.Context, filter any) (int64, error) {
	n, err := c.c.CountDocuments(ctx, filter)
	if err != nil {
		return 0, c.wrap("count", err)
	}
	return n, nil
}

// markOnce sets field to at on the one document matching filter, unless it is already set: the first time wins.
// A document that does not exist is core.ErrNotFound.
func (c col) markOnce(ctx context.Context, filter bson.D, field string, at time.Time) error {
	f := append(bson.D{}, filter...)
	f = append(f, bson.E{Key: field, Value: nil})
	res, err := c.c.UpdateOne(ctx, f, bson.D{{Key: "$set", Value: bson.D{{Key: field, Value: at}}}})
	if err != nil {
		return c.wrap("mark "+field, err)
	}
	if res.MatchedCount > 0 {
		return nil
	}
	n, err := c.count(ctx, filter)
	if err != nil {
		return err
	}
	if n == 0 {
		return c.notFound("mark " + field)
	}
	return nil
}

// findOne decodes the one document matching filter; no match is core.ErrNotFound.
func findOne[D any](ctx context.Context, c col, filter any) (D, error) {
	var d D
	err := c.c.FindOne(ctx, filter).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return d, c.notFound("get")
	}
	if err != nil {
		return d, c.wrap("get", err)
	}
	return d, nil
}

// findAll decodes every document matching filter, in the order of sort (nil: natural).
func findAll[D any](ctx context.Context, c col, filter, sort any, limit int64) ([]D, error) {
	opts := options.Find()
	if sort != nil {
		opts.SetSort(sort)
	}
	if limit > 0 {
		opts.SetLimit(limit)
	}
	cur, err := c.c.Find(ctx, filter, opts)
	if err != nil {
		return nil, c.wrap("list", err)
	}
	var out []D
	if err := cur.All(ctx, &out); err != nil {
		return nil, c.wrap("list", err)
	}
	return out, nil
}

// findAndUpdate runs findOneAndUpdate returning the document after the update; no match is mongo.ErrNoDocuments.
func findAndUpdate[D any](ctx context.Context, c col, filter, update any) (D, error) {
	var d D
	err := c.c.FindOneAndUpdate(ctx, filter, update,
		options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&d)
	return d, err
}

// stringIDs returns the _id (a string) of every document matching filter.
func stringIDs(ctx context.Context, c col, filter any) ([]string, error) {
	cur, err := c.c.Find(ctx, filter, options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, c.wrap("list ids", err)
	}
	var docs []struct {
		ID string `bson:"_id"`
	}
	if err := cur.All(ctx, &docs); err != nil {
		return nil, c.wrap("list ids", err)
	}
	ids := make([]string, len(docs))
	for i, d := range docs {
		ids[i] = d.ID
	}
	return ids, nil
}

// idIs builds the filter {_id: id}.
func idIs(id any) bson.D { return kv("_id", id) }

// set builds the update {$set: fields}.
func set(fields bson.D) bson.D { return bson.D{{Key: "$set", Value: fields}} }

// kv builds the one-field document {key: value}.
func kv(key string, value any) bson.D { return bson.D{{Key: key, Value: value}} }

// utc returns t in UTC.
func utc(t time.Time) time.Time { return t.UTC() }

// optTime returns a UTC copy of t, or nil.
func optTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
