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

	_, _ = db.Exec("drop table t2")

	result, err := db.Exec("create table t2(c1 float4, c2 double, c3 int1, c4 int2, c5 int4, c6 int8, c7 char(5), c8 varchar(10),c9 nchar(50), c10 nvarchar(120),c11 varbinary(12), c12 ST_GEOMETRY(12), DATE_PROD DATE, TIME_PROD TIME, INTERVAL_PROD INTERVAL,TIMESTMP TIMESTAMP,TIMETZ_PROD TIME WITH TIME ZONE, c18 bool);")
	if err != nil {
		fmt.Println("table was not created successfully", err, result)
	} else {
		fmt.Println("Table created successfully")
	}

	result, err = db.Exec("insert into t2 values (-1,-1,-1,-1,-1,-1,'','','ðŸ’®â‚¬ðŸ™‡ðŸ›','ð©¶˜â‚¬ðˆð¢±‘ð©¸½',x'68656c6c6f',x'68656c6c6f', '1991-1-1', '12:19:23', '1y4mon3d23h34m67s234565ms', '2016-11-11 03:59:08.8642','12:57:42 AEST', 'yes');")
	if err != nil {
		fmt.Println("row was not inserted successfully", err, result)
	} else {
		rows, _ := result.RowsAffected()
		fmt.Println(rows, "row inserted successfully")

	}

	result, err = db.Exec("insert into t2 values (-123.345, -23456.789, -128, -32768, -234567, -45678923,'xyz', 'Go lang','ðŸ’®â‚¬ðŸ™‡ðŸ›','ð©¶˜â‚¬ðˆð¢±‘ð©¸½',x'543b6c6c6f',x'123d6c6f', '2001-12-31', '23:59:59', '5y6mon7d23h21m67s897ms', '1996-12-11 23:59:08.1232','10:47:53 BST', 'false');")
	if err != nil {
		fmt.Println("row was not inserted successfully", err, result)
	} else {
		rows, _ := result.RowsAffected()
		fmt.Println(rows, "row inserted successfully")

	}

	result, err = db.Exec("insert into t2 values (123.345, 23456.789, 127, 32767, 234567, 45678923,'xyz', 'Go lang','ðŸ’®â‚¬ðŸ™‡ðŸ›','ð©¶˜â‚¬ðˆð¢±‘ð©¸½',x'543b6c6c6f',x'123d6c6f', '2001-12-31', '23:59:59', '5y6mon7d23h21m67s897ms', '1996-12-11 23:59:08.1232','10:47:53 BST','true');")
	if err != nil {
		fmt.Println("row was not inserted successfully", err, result)
	} else {
		rows, _ := result.RowsAffected()
		fmt.Println(rows, "row inserted successfully")

	}

	var ctx context.Context
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	var c1 float32
	var c2 float64
	var c3 int8
	var c4 int16
	var c5 int32
	var c6 int64
	var c7, c8, c9, c10, c11, c12, date_prod, time_prod, interval, timestamp, timetz string
	var c18 bool

	arg1 := [3]float32{-1, -123.345, 123.345}
	arg2 := [3]float64{-1, -23456.789, 23456.789}

	stmt, err := db.PrepareContext(ctx, "select * from t2 where c1 = ? and c2 = ?")
	if err != nil {
		fmt.Println("error in prepare statement", err)
	}
	defer stmt.Close()

	for i := 0; i < 3; i++ {

		rows, err := stmt.QueryContext(ctx, arg1[i], arg2[i])
		if err != nil {
			fmt.Println("call to stmt.QueryContext() failed: ", err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := rows.Scan(&c1, &c2, &c3, &c4, &c5, &c6, &c7, &c8, &c9, &c10, &c11, &c12, &date_prod, &time_prod, &interval, &timestamp, &timetz, &c18); err != nil {
				fmt.Println("call to rows.Scan() failed: ", err)
			}
			fmt.Printf("------------------------ \n")
			fmt.Printf("c1 is: %f \n", c1)
			fmt.Printf("c2 is: %f \n", c2)
			fmt.Printf("c3 is: %d \n", c3)
			fmt.Printf("c4 is: %d \n", c4)
			fmt.Printf("c5 is: %d \n", c5)
			fmt.Printf("c6 is: %d \n", c6)
			fmt.Printf("c7 is: %s \n", c7)
			fmt.Printf("c8 is: %s \n", c8)
			fmt.Printf("c9 is: %s \n", c9)
			fmt.Printf("c10 is: %s \n", c10)
			fmt.Printf("c11 is: %10x \n", c11)
			fmt.Printf("c12 is: %10x \n", c12)
			fmt.Printf("date_prod is: %s \n", date_prod)
			fmt.Printf("time_prod is: %s \n", time_prod)
			fmt.Printf("interval is: %s \n", interval)
			fmt.Printf("timestamp is: %s \n", timestamp)
			fmt.Printf("timetz is: %s \n", timetz)
			fmt.Println("c18 is: ", c18)

		}
	}

}
