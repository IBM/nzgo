package main

import (
	"context"
	"database/sql"
	"fmt"
	_ "log"

	"github.com/IBM/nzgo"
)

func main() {

	var conninfo string = "host=localhost user=admin password=password dbname=db1 port=5480 sslmode=disable "

	var elog nzgo.PDALogger
	elog.LogLevel = "debug"
	elog.LogPath = "/tmp/"
	elog.Initialize()

	db, err := sql.Open("nzgo", conninfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	_, _ = db.Exec("drop table t1")

	result, err := db.Exec("create table t1(c1 int,c2 int)")
	if err != nil {
		fmt.Println("table was not created successfully", err, result)
	} else {
		fmt.Println("Table created successfully")
	}

	result, err = db.Exec("insert into t1 values (1,3)")
	if err != nil {
		fmt.Println("row was not inserted successfully", err, result)
	} else {
		rows, _ := result.RowsAffected()
		fmt.Println(rows, "row inserted successfully")

	}

	var ctx context.Context
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	var c1, c2 int
	rows, err := db.QueryContext(ctx, "SELECT * FROM t1 WHERE c2 =?", 3)
	if err != nil {
		fmt.Println("error in prepare statement", err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&c1, &c2); err != nil {
			fmt.Println("error in prepare statement", err)
		}
		fmt.Printf("------------------------ \n")
		fmt.Printf("c1 is: %d \n", c1)
		fmt.Printf("c2 is: %d \n", c2)
	}
}
