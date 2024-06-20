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
   
    defer func() {
        if err := recover(); err != nil {
            fmt.Println("panic occurred:", err)
        }
    }()
    var c1 string
    rows, err := db.Query("SELECT jc->'user'->'first_name', jc->'user'->'first_name' from jt")
    if err != nil {
        fmt.Println(err)
    } else {
        for rows.Next() {
            rows.Scan(&c1)
            fmt.Printf("c1 is: %s \n", c1)
        }
    }
    
    rows, err = db.Query("SELECT jc->'user'->'first_name' from jt")
    if err != nil {
        fmt.Println(err)
    } else {
        for rows.Next() {
            rows.Scan(&c1)
            fmt.Printf("c1 is: %s \n", c1)
        }
    }

}

