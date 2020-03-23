package nzgo

//Interface coverage test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"testing"
)

const (
	conninfo = "user=admin " +
		"port=5480 " +
		"password=password " +
		"dbname=db2 " +
		//"host=9.32.247.36 " +
		//"securityLevel=1 " +
		//"sslmode=disable"
		"host=vmnps-dw31.svl.ibm.com " +
		"securityLevel=3 " +
		"sslmode=require" //verify-ca sslrootcert=C:/Users/sandeep_pawar/postgresql/root31.crt"
)

func openTestConnConninfo(conninfostr string) (*sql.DB, error) {
	elog := PDALogger{"DEBUG", ""}
	elog.Initialize()
	return sql.Open("nzgo", conninfostr)
}

func TestNewConnector_WorksWithOpenDB(t *testing.T) {
	elog := PDALogger{"DEBUG", ""}
	elog.Initialize()
	name := conninfo
	c, err := NewConnector(name)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(c)
	defer db.Close()
	// database/sql might not call our Open at all unless we do something with
	// the connection
	txn, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	txn.Rollback()
}

func TestNewConnector_Connect(t *testing.T) {
	fmt.Println("Interface Function check : Connect()")
	elog := PDALogger{"DEBUG", ""}
	elog.Initialize()
	name := conninfo
	c, err := NewConnector(name)
	if err != nil {
		t.Fatal(err)
	}
	db, err := c.Connect(context.Background()) //Interface Connector ->connect
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// database/sql might not call our Open at all unless we do something with
	// the connection
	txn, err := db.(driver.ConnBeginTx).BeginTx(context.Background(), driver.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	txn.Rollback()
}

func TestNewConnector_Driver(t *testing.T) {
	fmt.Println("Interface Function check : Driver()")
	elog := PDALogger{"DEBUG", ""}
	elog.Initialize()
	name := conninfo
	c, err := NewConnector(name)
	if err != nil {
		t.Fatal(err)
	}
	db, err := c.Driver().Open(name) //Connector -> driver interface
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// database/sql might not call our Open at all unless we do something with
	// the connection
	txn, err := db.(driver.ConnBeginTx).BeginTx(context.Background(), driver.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	txn.Rollback()
}

func TestRows_Next(t *testing.T) {
	fmt.Println("Interface Function check : rows->Next()")
	db, err := openTestConnConninfo(conninfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var c1t float32

	db.Exec(" drop table tdouble if exists;")
	db.Exec("create table tdouble(c1 float); ")
	db.Exec(" insert into tdouble values(323123123213213213213213213213.123123); ")
	rows, err := db.Query("select * from tdouble ")
	if err != nil {
		fmt.Println("call to get_work() failed: ", err)

	}

	for rows.Next() { //Interface rows->Next
		if err := rows.Scan(&c1t); err != nil {
			fmt.Println("call to get_work() failed: ", err)
		}
		//fmt.Printf("c1t is: %f \n", c1t)
	}
}

func TestRows_Columns(t *testing.T) {
	fmt.Println("Interface Function check : rows->Columns()")
	db, err := openTestConnConninfo(conninfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	db.Exec(" drop table testCol if exists;")
	db.Exec("create table testCol(c1 float4, c2 double, c3 int1, c4 int2, c5 int4, c6 int8, c7 char(5), c8 varchar(10))")
	db.Exec("insert into testCol values (-123.345, -23456.789, -128, -32768, -234567, -45678923,'xyz', 'Go lang')")
	rows, err := db.Query("select * from testCol ;")
	if err != nil {
		fmt.Println("call to get_work() failed: ", err)
	}
	fmt.Println(rows.Columns()) //Interface Rows->Columns
}

func TestRows_Close(t *testing.T) {
	fmt.Println("Interface Function check : rows->Close(), Next()")
	db, err := openTestConnConninfo(conninfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var c1t float32

	db.Exec(" drop table tdouble if exists;")
	db.Exec("create table tdouble(c1 float); ")
	db.Exec(" insert into tdouble values(12.34); ")
	db.Exec(" insert into tdouble values(12.45); ")

	rows, err := db.Query("select * from tdouble ")
	if err != nil {
		fmt.Println("call to get_work() failed: ", err)

	}
	for rows.Next() { //Interface rows->Next
		if err := rows.Scan(&c1t); err != nil {
			fmt.Println("call to get_work() failed: ", err)
		}
		fmt.Printf("c1t is: %f \n", c1t)
		//	      rows.Close() //Interface Rows->Close  --Check more
	}
}

func TestPinger_Ping(t *testing.T) {
	fmt.Println("Interface Function check : Ping()")
	db, err := openTestConnConninfo(conninfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Ping Successful")
}

func TestDriver_Open(t *testing.T) {
	fmt.Println("Interface Function check(Calls internally) : Open()")
	db, err := openTestConnConninfo(conninfo) //calls interface internally
	if err != nil {
		panic(err)
	}
	defer db.Close()

	fmt.Println("Open/Close connection success")
}

//Only first query gets executed on nps
func TestRowsNextResultSet_MultipleResult(t *testing.T) {
	fmt.Println("Interface Function check : rows->HasNextResultSet(), rows->NextResultSet()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	rows, err := db.Query("		begin;			select * from information_schema.tables limit 1;			select * from information_schema.columns limit 2;		commit;")
	if err != nil {
		t.Fatal(err)
	}
	type set struct {
		cols     []string
		rowCount int
	}
	buf := []*set{}
	for {
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		s := &set{
			cols: cols,
		}
		buf = append(buf, s)

		for rows.Next() {
			s.rowCount++
		}
		//Also check rows.HasNextResultSet()
		if !rows.NextResultSet() {
			break
		}
	}
}

func TestConn_BeginCloseRollback(t *testing.T) {
	fmt.Println("Interface Function check : Conn->Close(),Begin(); Tx->Rollback()")
	conn, err := openTestConnConninfo(conninfo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //Interface conn->close

	txn, err := conn.Begin() //Interface conn->Begin
	if err != nil {
		t.Fatalf("%#v", err)

	}
	rows, err := txn.Query("SELECT USER") //Internally calls conn->query() and not Query()
	if err != nil {
		txn.Rollback()
		t.Fatalf("%#v", err)
	} else {
		rows.Close()
		//fmt.Printf("Ok ")
	}
	txn.Rollback() //Interface Tx->Rollback()
	//txn.Commit()//Interface Tx->Commit() //creates problem here

}

func TestTx_Commit(t *testing.T) {
	fmt.Println("Interface Function check : Tx->Commit()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Commit() //Interface tx->Commit()

	rows, err := tx.Query("select 1")
	if err != nil {
		t.Fatal(err)
	}

	if rows.Next() {
		var val int32
		if err = rows.Scan(&val); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("Expected at least one row in first query in xact")
	}

	rows2, err := tx.Query("select 2")
	if err != nil {
		t.Fatal(err)
	}

	if rows2.Next() {
		var val2 int32
		if err := rows2.Scan(&val2); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("Expected at least one row in second query in xact")
	}

	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}

	if err = rows2.Err(); err != nil {
		t.Fatal(err)
	}

	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestResult_RowsAffected(t *testing.T) {
	fmt.Println("Interface Function check : Conn->Exec(), Result->RowsAffected(), Result->LastInsertId()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	db.Exec(" drop table tTemp if exists;")
	_, err := db.Exec("CREATE TEMP TABLE tTemp (a int)") //Interface Execer->Exec()
	if err != nil {
		t.Fatal(err)
	}

	r, err := db.Exec("INSERT INTO tTemp VALUES (1)")
	if err != nil {
		t.Fatal(err)
	}

	if n, _ := r.RowsAffected(); n != 1 {
		t.Fatalf("expected 1 row affected, not %d", n)
	}
	val, _ := r.RowsAffected() //Interface Result->RowsAffected()
	id, _ := r.LastInsertId()  //Interface Result->LastInsertId()
	fmt.Println("Rows Affected : ", val)
	fmt.Println("Last Inserted Id : ", id)
	r, err = db.Exec("INSERT INTO tTemp VALUES (3)")
	val, _ = r.RowsAffected() //Interface Result->RowsAffected()
	id, _ = r.LastInsertId()  //Interface Result->LastInsertId()
	fmt.Println("Rows Affected : ", val)
	fmt.Println("Last Inserted Id : ", id)

	db.Exec("INSERT INTO tTemp VALUES (1)")
	r, err = db.Exec("delete from tTemp where a=1;")
	val, _ = r.RowsAffected() //Interface Result->RowsAffected()
	fmt.Println("Rows Affected : ", val)

}

func TestExecerContext_ExecContext(t *testing.T) {
	fmt.Println("Interface Function check : Conn->ExecContext()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := db.ExecContext(ctx, "drop table tdouble if exists;"); err != nil { //Interface ExecerContext->ExecContext()
		t.Fatal(err)
	}

}

func TestQueryerContext_QueryContext(t *testing.T) {
	fmt.Println("Interface Function check : Conn->QueryContext()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := db.QueryContext(ctx, "select 1"); err != nil { //Interface ExecerContext->QueryContext()
		t.Fatal(err)
	}
}

func TestConn_Prepare(t *testing.T) {
	fmt.Println("Interface Function check : Conn->Prepare()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	st, err := db.Prepare("SELECT 1") //Interface conn->Prepare()
	if err != nil {
		t.Fatal(err)
	}

	st1, err := db.Prepare("SELECT 2")
	if err != nil {
		t.Fatal(err)
	}

	r, err := st.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if !r.Next() {
		t.Fatal("expected row")
	}

	var i int
	err = r.Scan(&i)
	if err != nil {
		t.Fatal(err)
	}

	if i != 1 {
		t.Fatalf("expected 1, got %d", i)
	}

	// st1

	r1, err := st1.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()

	if !r1.Next() {
		if r.Err() != nil {
			t.Fatal(r1.Err())
		}
		t.Fatal("expected row")
	}

	err = r1.Scan(&i)
	if err != nil {
		t.Fatal(err)
	}

	if i != 2 {
		t.Fatalf("expected 2, got %d", i)
	}
}

func TestRows_ColumnInfo(t *testing.T) {
	fmt.Println("Interface Function check(Calls internally) : ColumnTypeLength(), ColumnTypePrecisionScale(), ColumnTypeScanType(), ColumnTypeDatabaseTypeName()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	rows, err := db.Query("select * from information_schema.tables limit 1;                    ")
	if err != nil {
		fmt.Println("call to db.Query() failed: ", err)

	}
	_, _ = rows.ColumnTypes() //calls internally
	//Interface ColumnTypeLength(), ColumnTypePrecisionScale(), ColumnTypeScanType(), ColumnTypeDatabaseTypeName()
}

func TestStmt_QueryExecCloseNumInput(t *testing.T) {
	fmt.Println("Interface Function check : stmt->Query(), stmt->Exec() ; Calls internally : stmt->NumInput(), stmt->close(), conn->Close()")
	db, _ := openTestConnConninfo(conninfo)
	defer db.Close()

	st, err := db.Prepare("SELECT 1") //Interfcae stmt->NumInput() internally called
	if err != nil {
		t.Fatal(err)
	}

	r, err := st.Query() //Interface stmt->Query()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //Interface stmt->close() conn->Close() will be called internally

	if !r.Next() {
		t.Fatal("expected row")
	}

	var i int
	err = r.Scan(&i)
	if err != nil {
		t.Fatal(err)
	}

	if i != 1 {
		t.Fatalf("expected 1, got %d", i)
	}

	st2, _ := db.Prepare("drop table tdouble if exists;")
	st2.Exec() //Interface stmt->Exec()

}
