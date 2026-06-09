// Command authz-migrate applies the llm-agent-authz schema to the database in
// LLM_AGENT_AUTHZ_PG_URL (or --dsn).
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/costa92/llm-agent-authz/store"
)

func main() {
	dsn := flag.String("dsn", os.Getenv("LLM_AGENT_AUTHZ_PG_URL"), "Postgres DSN")
	flag.Parse()
	if *dsn == "" {
		log.Fatal("authz-migrate: set LLM_AGENT_AUTHZ_PG_URL or pass --dsn")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		log.Fatalf("authz-migrate: connect: %v", err)
	}
	defer pool.Close()
	if err := store.New(pool).Migrate(ctx); err != nil {
		log.Fatalf("authz-migrate: migrate: %v", err)
	}
	log.Printf("authz-migrate: schema at head version %d", store.HeadSchemaVersion)
}
