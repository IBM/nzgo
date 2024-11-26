package main

import (
	_ "context"
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

	var c1, c2 sql.NullString
	rows, err := db.Query("select NULL,version()")
	if err != nil {
		fmt.Println("call to db.Query() failed: ", err)
	}
	for rows.Next() {
		rows.Scan(&c1, &c2)
		if !c1.Valid {
			fmt.Printf("c1 is: NULL \n")
		} else {
			fmt.Printf("c1 is: %s \n", c1.String)
		}
		if !c2.Valid {
			fmt.Printf("c1 is: NULL \n")
		} else {
			fmt.Printf("c1 is: %s \n", c2.String)
		}
	}
}
