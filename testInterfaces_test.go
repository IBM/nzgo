package nzgo

//Interface coverage test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"runtime/debug"
	"strings"
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

const (
	JSON     int = 0
	JSONB    int = 1
	INT      int = 2
	JSONPATH int = 3
)

type row struct {
	id   sql.NullInt32
	json sql.NullString
}

type column struct {
	typ  int
	name string
}
type table struct {
	name string
	cols []column
}

const JSON_SERVER_VERSION = "Release 11.0.3.0"

const JSONB_SERVER_VERSION = "Release 11.2.0.0" // version is new enough (JSONB datatype is not released yet)

const JSON_OPER_SERVER_VERSION = JSONB_SERVER_VERSION

func checkErr(expErr bool, err error, t *testing.T) {
	if expErr && err == nil {
		t.Log(`Expect error, but there was no error.`)
	} else if !expErr && err != nil {
		t.Logf(`Expect no error, but have error "%s".`, err)
	} else {
		return
	}
	t.Fatalf(string(debug.Stack()))
}

func query(db *sql.DB, sqlStatement string, expErr bool, t *testing.T) (error, *sql.Rows) {
	fmt.Println(sqlStatement)
	rows, err := db.Query(sqlStatement)
	checkErr(expErr, err, t)
	return err, rows
}

func exec(db *sql.DB, sqlStatement string, expErr bool, t *testing.T) error {
	fmt.Println(sqlStatement)
	_, err := db.Exec(sqlStatement)
	checkErr(expErr, err, t)
	return err
}

func _select(db *sql.DB, sqlStatement string, expErr bool, t *testing.T) {
	err, rows := query(db, sqlStatement, expErr, t)
	if err == nil {
		defer rows.Close()
		printTable(rows, t)
	} else {
		fmt.Println(err)
	}
}

func insert(db *sql.DB, table table, val1 int, val2 string, expErr bool, t *testing.T) {
	sqlStatement := fmt.Sprintf(`INSERT INTO %v(%v, %v) VALUES (%v, %v)`,
		table.name,
		table.cols[0].name,
		table.cols[1].name,
		val1,
		val2)
	fmt.Println(sqlStatement)
	res, err := db.Exec(sqlStatement)
	checkErr(expErr, err, t)
	rowsAffected, err := res.RowsAffected()
	checkErr(expErr, err, t)
	fmt.Printf("INSERT %v\n", rowsAffected)
}

func drop(db *sql.DB, table table) {
	sqlStatement := fmt.Sprintf(`DROP TABLE %v IF EXISTS`, table.name)
	fmt.Println(sqlStatement)
	_, err := db.Exec(sqlStatement)
	if err != nil {
		fmt.Println("ERROR: ", err)
	} else {
		fmt.Println("DROP TABLE")
	}
}

func selectAll(db *sql.DB, table table, expErr bool, t *testing.T) {
	sqlStatement := fmt.Sprintf(`SELECT * FROM %v`, table.name)
	_select(db, sqlStatement, expErr, t)
}

func selectWithJsonOper(db *sql.DB, table table, oper string, expErr bool, t *testing.T) {
	sqlStatement := fmt.Sprintf(`SELECT %v, %v %v FROM %v`,
		table.cols[0].name,
		table.cols[1].name,
		oper,
		table.name,
	)
	_select(db, sqlStatement, expErr, t)
}

func selectWithJsonFunc(db *sql.DB, table table, f string, expErr bool, t *testing.T) {
	sqlStatement := fmt.Sprintf(`SELECT %v, %v(%v) FROM %v`,
		table.cols[0].name,
		f,
		table.cols[1].name,
		table.name,
	)
	_select(db, sqlStatement, expErr, t)
}

func printTable(rows *sql.Rows, t *testing.T) {
	columns, err := rows.Columns()
	checkErr(false, err, t)
	fmt.Printf("%3v | %v\n", columns[0], columns[1])
	fmt.Printf("----+----------------------------------\n")
	for rows.Next() {
		checkErr(false, rows.Err(), t)
		row := row{}
		err = rows.Scan(
			&row.id,
			&row.json,
		)
		checkErr(false, err, t)

		fmt.Printf("%3v | %v\n", row.id.Int32, row.json.String)
	}
}

func type2Str(typ int) string {
	switch typ {
	case JSON:
		return "JSON"
	case JSONB:
		return "JSONB"
	case JSONPATH:
		return "JSONPATH"
	case INT:
		return "INT"
	default:
		panic("type2Str: Unknown datatype")
	}
}

func create(db *sql.DB, table table, expErr bool, t *testing.T) {
	sqlStatement := fmt.Sprintf(`CREATE TABLE %v(%v %v, %v %v)`,
		table.name,
		table.cols[0].name,
		type2Str(table.cols[0].typ),
		table.cols[1].name,
		type2Str(table.cols[1].typ))
	fmt.Println(sqlStatement)
	_, err := db.Exec(sqlStatement)
	checkErr(expErr, err, t)
	fmt.Println("CREATE TABLE")
}

func serverVersion(db *sql.DB, t *testing.T) string {
	err, rows := query(db, `select system_software_version from _v_system_info`, false, t)
	if err != nil {
		t.Fatalf("Failed to get server version")
	}
	_, err = rows.Columns()
	checkErr(false, err, t)
	ret := ""
	if rows.Next() {
		checkErr(false, rows.Err(), t)
		err = rows.Scan(&ret)
		checkErr(false, err, t)
	}
	return ret
}

func versionCompare(v1 string, v2 string) int {
	var major1, minor1, sub_minor1, variant1 int = 0, 0, 0, 0
	var major2, minor2, sub_minor2, variant2 int = 0, 0, 0, 0
	_, err := fmt.Sscanf(strings.Split(v1, " ")[1], "%d.%d.%d.%d", &major1, &minor1, &sub_minor1, &variant1)
	if err != nil {
		return -1
	}
	_, err = fmt.Sscanf(strings.Split(v2, " ")[1], "%d.%d.%d.%d", &major2, &minor2, &sub_minor2, &variant2)
	if err != nil {
		return -1
	}

	if (major1 == major2) && (minor1 == minor2) && (sub_minor1 == sub_minor2) && (variant1 == variant2) {
		return 0
	}

	if major1 > major2 {
		return 1
	}
	if major1 < major2 {
		return -1
	} else {
		if minor1 > minor2 {
			return 1
		}
		if minor1 < minor2 {
			return -1
		} else {
			if sub_minor1 > sub_minor2 {
				return 1
			}
			if sub_minor1 < sub_minor2 {
				return -1
			} else {
				if variant1 > variant2 {
					return 1
				} else {
					return -1
				}
			}
		}
	}
}

func setupTable(db *sql.DB, table table, t *testing.T) {
	sv := serverVersion(db, t)
	if versionCompare(sv, JSON_SERVER_VERSION) < 0 && table.cols[1].typ == JSON {
		t.Skipf("Server does not have JSON support")
	} else if versionCompare(sv, JSONB_SERVER_VERSION) < 0 && table.cols[1].typ == JSONB {
		t.Skipf("Server does not have JSONB support")
	}

	drop(db, table)
	create(db, table, false, t)
	insert(db, table, 1, `'{"言語":"日本語"}'`, false, t)
	insert(db, table, 2, `'{"言語":"中文"}'`, false, t)
	insert(db, table, 3, `'{"言語":"русский"}'`, false, t)
	insert(db, table, 4, `'{"言語":"アラビア語"}'`, false, t)
	insert(db, table, 5, `'{"言語":"Tiếng Việt"}'`, false, t)
}

func setupJsonpathTable(db *sql.DB, table table, t *testing.T) {
	sv := serverVersion(db, t)
	if versionCompare(sv, JSONB_SERVER_VERSION) < 0 && table.cols[1].typ == JSONPATH {
		t.Skipf("Server does not have JSONPATH support")
	}

	drop(db, table)
	create(db, table, false, t)
	insert(db, table, 1, `'$[0]'`, false, t)
	insert(db, table, 2, `'$[*].a'`, false, t)
}

func tearDownTable(db *sql.DB, table table, t *testing.T) {
	drop(db, table)
}

func TestJsonpath(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)
	checkErr(false, err, t)
	defer db.Close()

	table := table{"jsonpath_table", []column{{INT, "id"}, {JSONPATH, "jsonpath_col"}}}
	setupJsonpathTable(db, table, t)

	selectAll(db, table, false, t)

	tearDownTable(db, table, t)

}

func TestJson(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)
	checkErr(false, err, t)
	defer db.Close()

	table := table{"json_table", []column{{INT, "id"}, {JSON, "json_col"}}}
	setupTable(db, table, t)

	selectAll(db, table, false, t)

	tearDownTable(db, table, t)

	}

func TestJsonb(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)
	checkErr(false, err, t)
	defer db.Close()

	table := table{"jsonb_table", []column{{INT, "id"}, {JSONB, "jsonb_col"}}}
	setupTable(db, table, t)

	selectAll(db, table, false, t)

	tearDownTable(db, table, t)

}

func TestJsonbOperator(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)
	checkErr(false, err, t)
	defer db.Close()

	table := table{"jsonb_table", []column{{INT, "id"}, {JSONB, "jsonb_col"}}}
	setupTable(db, table, t)

	selectWithJsonOper(db, table, `||  '{"cómo estás":"お元気ですか"}'`, false, t)
	selectWithJsonOper(db, table, `-   '言語'::NVARCHAR(100)`, false, t)
	selectWithJsonOper(db, table, `-   '"言語"'`, false, t)
	selectWithJsonOper(db, table, `-   '["言語", "Non-existent key"]'`, false, t)
	selectWithJsonOper(db, table, `?   '言語'`, false, t)
	selectWithJsonOper(db, table, `?   'Non-existent key'`, false, t)
	selectWithJsonOper(db, table, `?|  '["言語", "Non-existent key"]'`, false, t)
	selectWithJsonOper(db, table, `?|  '["Non-existent key 1", "Non-existent key 2"]'`, false, t)
	selectWithJsonOper(db, table, `?&  '["言語", "Non-existent key"]'`, false, t)
	selectWithJsonOper(db, table, `?&  '["言語", "言語"]'`, false, t)
	selectWithJsonOper(db, table, `@>  '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `<@  '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `=   '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `!=  '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `<>  '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `>   '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `>=  '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `<   '{"言語":"日本語"}'`, false, t)
	selectWithJsonOper(db, table, `<=  '{"言語":"日本語"}'`, false, t)
	selectWithJsonFunc(db, table, `jsonb_pretty`, false, t)

	tearDownTable(db, table, t)

}

func TestJsonOperator(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)
	checkErr(false, err, t)
	defer db.Close()

	table := table{"json_table", []column{{INT, "id"}, {JSON, "json_col"}}}
	setupTable(db, table, t)

	sv := serverVersion(db, t)
	if versionCompare(sv, JSON_OPER_SERVER_VERSION) < 0 {
		t.Skipf("Server does not have JSON operator support")
	}

	selectWithJsonOper(db, table, `->  '言語'`, false, t)
	selectWithJsonOper(db, table, `->> '言語'`, false, t)
	selectWithJsonOper(db, table, `->  'Non-existent key'`, false, t)
	selectWithJsonOper(db, table, `->> 'Non-existent key'`, false, t)

	tearDownTable(db, table, t)

}

func TestJsonClientVersion(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)

	checkErr(false, err, t)
	defer db.Close()

	table := table{"json_table", []column{{INT, "id"}, {JSON, "json_col"}}}
	setupTable(db, table, t)

	exec(db, fmt.Sprintf("SET CLIENT_VERSION = '%s'", "Release 11.0.10.0"), false, t) // without JSON
	selectAll(db, table, true, t)                                                     // expect error

	exec(db, fmt.Sprintf("SET CLIENT_VERSION = '%s'", "Release 11.1.0.0"), false, t) // with JSON
	selectAll(db, table, false, t)                                                   // ok

	exec(db, fmt.Sprintf("SET CLIENT_VERSION = '%s'", "Release 11.1.1.0"), false, t) // Future versions, with JSON
	selectAll(db, table, false, t)                                                   // ok

	tearDownTable(db, table, t)

}

func TestJsonBackwardCompatibility(t *testing.T) {
	db, err := openTestConnConninfo(conninfo)

	checkErr(false, err, t)
	defer db.Close()

	table := table{"json_table", []column{{INT, "id"}, {JSON, "json_col"}}}
	setupTable(db, table, t)

	exec(db, fmt.Sprintf("SET CLIENT_VERSION = '%s'", "Release 11.0.10.0"), false, t) // no JSON
	selectAll(db, table, true, t)                                                     // expect error

	exec(db, "SET DATATYPE_BACKWARD_COMPATIBILITY ON", false, t)
	selectAll(db, table, false, t) // ok

	tearDownTable(db, table, t)

}
