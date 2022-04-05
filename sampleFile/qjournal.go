package qjournal

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	config "qlife-be/internal/config"
	qjournalEntity "qlife-be/internal/entity/qlife/qjournal"
	"qlife-be/pkg/errors"
	jaegerLog "qlife-be/pkg/log"

	"github.com/jmoiron/sqlx"
	"github.com/opentracing/opentracing-go"
)

type (
	// Data ...
	Data struct {
		db   *sqlx.DB
		stmt map[string]*sqlx.Stmt

		tracer opentracing.Tracer
		logger jaegerLog.Factory
	}

	// statement ...
	statement struct {
		key   string
		query string
	}
)

// Const ...
const (
	vault_token = "s.XvcDZiqLYLOrdhL9zmYHbGU0"
	// SELECT
	getQJournalDataByMemberID  = "GetQJournalDataByMemberID"
	qGetQJournalDataByMemberID = `
	SELECT  
		JournalRunningID,
		JournalID,
		JournalMemberID,
		JournalMemberName,
		JournalUserName,
		JournalDate,         
		JournalTime,
		JournalSymptomCategoryID,
		JournalSymptomName,
		JournalSymptomID,
		JournalIntensity,
		JournalIntensityDescription,
		JournalAdditionalInformation,
		JournalDiseaseCategoryID,
		JournalDiseaseID,
		JournalDiseaseName,
		JournalCreatedDate,
		JournalLastupdate   
	FROM q_life.t_journal 
	WHERE JournalMemberID = ?`

	getALLQJournalIDByMemberID  = "GetALLQJournalIDByMemberID"
	qGetALLQJournalIDByMemberID = `
	SELECT  DISTINCT
		JournalID
	FROM q_life.t_journal 
	WHERE JournalMemberID = ?`

	getLastJournalID  = "GetLastJournalID"
	qGetLastJournalID = `
	SELECT 
		JournalRunningID,
		JournalID
	FROM  q_life.t_journal 
	WHERE JournalID != '0'
	ORDER BY JournalCreatedDate DESC
	LIMIT 1`

	// -------------Improvement-------------

	getQImprovementDataByMemberID  = "GetQImprovementDataByMemberID"
	qGetQImprovementDataByMemberID = `
	SELECT  
		ImprovementRunningID,
		ImprovementID,
		ImprovementMemberID,
		ImprovementMemberName,
		ImprovementJournalID,
		ImprovementSymptomID,
		ImprovementRemedyID,
		ImprovementRemedyName,
		ImprovementDate,
		ImprovementTime,
		ImprovementCreatedDate,
		ImprovementLastUpdated  
	FROM q_life.t_improvement 
	WHERE ImprovementMemberID = ?`

	getQImprovementlDataByJournalIDAndMemberID  = "GetQImprovementlDataByJournalIDAndMemberID"
	qGetQImprovementlDataByJournalIDAndMemberID = `
	SELECT  
		ImprovementRunningID,
		ImprovementID,
		ImprovementMemberID,
		ImprovementMemberName,
		ImprovementJournalID,
		ImprovementSymptomID,
		ImprovementRemedyID,
		ImprovementRemedyName,
		ImprovementDate,
		ImprovementTime,
		ImprovementCreatedDate,
		ImprovementLastUpdated  
	FROM q_life.t_improvement 
	WHERE ImprovementJournalID = ? AND ImprovementMemberID = ?`

	getLastImprovementID  = "GetLastImprovementID"
	qGetLastImprovementID = `
	SELECT 
		ImprovementRunningID,
		ImprovementID
	FROM  q_life.t_improvement 
	WHERE ImprovementID != '0'
	ORDER BY ImprovementCreatedDate DESC
	LIMIT 1`

	// INSERT
	insertNewJurnalData  = "InsertNewJurnalData"
	qInsertNewJurnalData = `Insert INTO q_life.t_journal 
	(
		JournalRunningID,
		JournalID,
		JournalMemberID,
		JournalMemberName,
		JournalUserName,
		JournalDate,         
		JournalTime,
		JournalSymptomCategoryID,
		JournalSymptomName,
		JournalSymptomID,
		JournalIntensity,
		JournalIntensityDescription,
		JournalAdditionalInformation,
		JournalDiseaseCategoryID,
		JournalDiseaseID,
		JournalDiseaseName,
		JournalImprovementYN,
		JournalCreatedDate,
		JournalLastupdate   
    )
    VALUES
    (
		NULL,
		?,
		?,
		?,
		?,
		?,         
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		'N',
		CURRENT_TIMESTAMP,
		CURRENT_TIMESTAMP
    )`

	// -------------Improvement-------------
	insertNewImprovementData  = "InsertNewImprovementData"
	qInsertNewImprovementData = `Insert INTO q_life.t_improvement 
	(
		ImprovementRunningID,
		ImprovementID,
		ImprovementMemberID,
		ImprovementMemberName,
		ImprovementJournalID,
		ImprovementSymptomID,
		ImprovementRemedyID,
		ImprovementRemedyName,
		ImprovementDate,
		ImprovementTime,
		ImprovementCreatedDate,
		ImprovementLastUpdated
    )
    VALUES
    (
		NULL,
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		?,
		CURRENT_TIMESTAMP,
		CURRENT_TIMESTAMP
    )`

	// UPDATE
	updateImprovementYNBYJournalID  = "UpdateImprovementYNBYJournalID"
	qUpdateImprovementYNBYJournalID = `UPDATE q_life.t_journal SET JournalImprovementYN = 'Y' WHERE JournalID = ?`

// DELETE
)

// Var ...
var (
	readStmt = []statement{
		{getLastJournalID, qGetLastJournalID},
		{getLastImprovementID, qGetLastImprovementID},
		{getQJournalDataByMemberID, qGetQJournalDataByMemberID},
		{getALLQJournalIDByMemberID, qGetALLQJournalIDByMemberID},
		{getQImprovementDataByMemberID, qGetQImprovementDataByMemberID},
		{getQImprovementlDataByJournalIDAndMemberID, qGetQImprovementlDataByJournalIDAndMemberID},
	}
	insertStmt = []statement{
		{insertNewJurnalData, qInsertNewJurnalData},
		{insertNewImprovementData, qInsertNewImprovementData},
	}
	updateStmt = []statement{
		{updateImprovementYNBYJournalID, qUpdateImprovementYNBYJournalID},
	}
	deleteStmt = []statement{}
)

// New ...
func New(db *sqlx.DB, tracer opentracing.Tracer, logger jaegerLog.Factory) Data {
	d := Data{
		db:     db,
		tracer: tracer,
		logger: logger,
	}

	d.authenticate(true)
	return d
}

func (d *Data) initStmt() {
	var (
		err   error
		stmts = make(map[string]*sqlx.Stmt)
	)

	for _, v := range readStmt {
		stmts[v.key], err = d.db.PreparexContext(context.Background(), v.query)
		if err != nil {
			log.Fatalf("[DB] Failed to initialize select statement key %v, err : %v", v.key, err)
		}
	}

	for _, v := range insertStmt {
		stmts[v.key], err = d.db.PreparexContext(context.Background(), v.query)
		if err != nil {
			log.Fatalf("[DB] Failed to initialize insert statement key %v, err : %v", v.key, err)
		}
	}

	for _, v := range updateStmt {
		stmts[v.key], err = d.db.PreparexContext(context.Background(), v.query)
		if err != nil {
			log.Fatalf("[DB] Failed to initialize update statement key %v, err : %v", v.key, err)
		}
	}

	for _, v := range deleteStmt {
		stmts[v.key], err = d.db.PreparexContext(context.Background(), v.query)
		if err != nil {
			log.Fatalf("[DB] Failed to initialize delete statement key %v, err : %v", v.key, err)
		}
	}

	d.stmt = stmts
}
func (d *Data) checkConnection(ctx context.Context) {
	fmt.Println("CHECK CONNECTION")
	cfg := config.Get()
	fmt.Println("Config", cfg.Database.Aurora)
	fmt.Println("DB", d.db.Stats())
	err := d.db.PingContext(ctx)
	if err != nil {
		fmt.Println("Err", err)
		if strings.Contains(err.Error(), "Access denied") {
			fmt.Println("TEST")
			d.authenticate(false)
		} else if strings.Contains(err.Error(), "bad connection") {
			fmt.Println("TEST")
			d.authenticate(false)
		} else if strings.Contains(err.Error(), "database is closed") {
			fmt.Println("TEST")
			d.authenticate(true)
		}
	}
}

func (d *Data) authenticate(i bool) {
	fmt.Println("Authenticate")

	err := config.Init()
	if err != nil {
		fmt.Println("Error get config file")
	}
	cfg := config.Get()

	if !i {
		fmt.Println("Closing DB")
		// d.db.Close()
		// err = d.db.Ping()
		// if err != nil {
		// 	fmt.Println("Error PING", err)
		// }
	}

	fmt.Println("Config ATAS", cfg.Database.Aurora)
	d.db, err = sqlx.Open("mysql", cfg.Database.Aurora)
	fmt.Println("Config BAWAH", cfg.Database.Aurora)
	if err != nil {
		fmt.Println("Error Connection", err)
	}
	fmt.Println("DB", d.db.Stats())
	err = d.db.Ping()
	if err != nil {
		fmt.Println("Error Ping", err)
	}

	d.initStmt()

}

// JOURNAL

// GenerateJournalID ...
func (d Data) GenerateJournalID(ctx context.Context) (string, error) {
	var (
		// res      qLifeEntity.MemberData
		last      qjournalEntity.JournalData
		journalID string
		err       error
	)
	d.checkConnection(ctx)

	now := time.Now()
	year := fmt.Sprintf("%02d", now.Year())
	month := fmt.Sprintf("%02d", now.Month())

	if err := d.stmt[getLastJournalID].QueryRowxContext(ctx).StructScan(&last); err != nil {
		if err == sql.ErrNoRows {
			last.JournalID = fmt.Sprintf("%s%s%s%06d", "J", year[2:], month, 0)
		} else {
			return journalID, errors.Wrap(err, "[DATA][GenerateJournalID]")
		}
	}

	if last.JournalID[:5] == "J"+year[2:]+month {
		temp := strings.SplitAfterN(last.JournalID, "", 6)
		res, _ := strconv.Atoi(temp[5])

		journalID = fmt.Sprintf("%s%s%s%06d", "J", year[2:], month, res+1)
	} else {

		journalID = fmt.Sprintf("%s%s%s%06d", "J", year[2:], month, 1)
	}

	return journalID, err
}

//  target
// GetQJournalDataByMemberID ...
func (d Data) GetQJournalDataByMemberID(ctx context.Context, memberID string) ([]qjournalEntity.JournalData, error) {
	var (
		rows  *sqlx.Rows
		data  qjournalEntity.JournalData
		datas []qjournalEntity.JournalData
		err   error
	)
	d.checkConnection(ctx)

	rows, err = d.stmt[getQJournalDataByMemberID].QueryxContext(ctx, memberID)
	for rows.Next() {
		if err = rows.StructScan(&data); err != nil {
			return datas, errors.Wrap(err, "[DATA][GetDiseaseBySymptom]")
		}
		datas = append(datas, data)
	}
	defer rows.Close()

	return datas, err
}

// GetALLQJournalIDByMemberID ...
func (d Data) GetALLQJournalIDByMemberID(ctx context.Context, memberID string) ([]string, error) {
	var (
		rows  *sqlx.Rows
		data  qjournalEntity.JournalData
		datas []string
		err   error
	)
	d.checkConnection(ctx)

	rows, err = d.stmt[getALLQJournalIDByMemberID].QueryxContext(ctx, memberID)
	for rows.Next() {
		if err = rows.StructScan(&data); err != nil {
			return datas, errors.Wrap(err, "[DATA][GetDiseaseBySymptom]")
		}
		fmt.Println("data", data)
		datas = append(datas, data.JournalID)
	}
	defer rows.Close()

	return datas, err
}

// InsertNewJurnalData ...
func (d Data) InsertNewJurnalData(ctx context.Context, data qjournalEntity.JournalData) error {
	var (
		err error
	)
	d.checkConnection(ctx)

	tempD, _ := time.Parse("02-01-2006", data.JournalDate)
	tempT, _ := time.Parse("15:04:05", data.JournalTime)
	fmt.Println(tempD, tempT)

	if _, err = d.stmt[insertNewJurnalData].ExecContext(ctx,
		data.JournalID,
		data.JournalMemberID,
		data.JournalMemberName,
		data.JournalUserName,
		tempD,
		tempT.Format("15:04:05"),
		data.JournalSymptomCategoryID,
		data.JournalSymptomName,
		data.JournalSymptomID,
		data.JournalIntensity,
		data.JournalIntensityDescription,
		data.JournalAdditionalInformation,
		data.JournalDiseaseCategoryID,
		data.JournalDiseaseID,
		data.JournalDiseaseName,
	); err != nil {
		return errors.Wrap(err, "[DATA][InsertNewJurnalData]")
	}

	return err
}

// UpdateImprovementYNByJournalID ...
func (d Data) UpdateImprovementYNByJournalID(ctx context.Context, journalID string) error {
	var err error
	d.checkConnection(ctx)

	if _, err = d.stmt[updateImprovementYNBYJournalID].ExecContext(ctx,
		journalID,
	); err != nil {
		return errors.Wrap(err, "[DATA][UpdateImprovementYNByJournalID]")
	}

	return err
}

// IMPROVEMENT

// GenerateImprovementID ...
func (d Data) GenerateImprovementID(ctx context.Context) (string, error) {
	var (
		// res      qLifeEntity.MemberData
		last          qjournalEntity.ImprovementData
		improvementID string
		err           error
	)

	d.checkConnection(ctx)

	now := time.Now()
	year := fmt.Sprintf("%02d", now.Year())
	month := fmt.Sprintf("%02d", now.Month())

	if err := d.stmt[getLastImprovementID].QueryRowxContext(ctx).StructScan(&last); err != nil {
		if err == sql.ErrNoRows {
			last.ImprovementID = fmt.Sprintf("%s%s%s%06d", "I", year[2:], month, 0)
		} else {
			return improvementID, errors.Wrap(err, "[DATA][GenerateImprovementID]")
		}
	}

	fmt.Println("LAST", last)

	if last.ImprovementID[:5] == "I"+year[2:]+month {
		temp := strings.SplitAfterN(last.ImprovementID, "", 6)
		res, _ := strconv.Atoi(temp[5])

		improvementID = fmt.Sprintf("%s%s%s%06d", "I", year[2:], month, res+1)
	} else {

		improvementID = fmt.Sprintf("%s%s%s%06d", "I", year[2:], month, 1)
	}

	return improvementID, err
}

// InsertNewImprovementData ...
func (d Data) InsertNewImprovementData(ctx context.Context, data qjournalEntity.ImprovementData) error {
	var (
		err error
	)

	d.checkConnection(ctx)

	tempD, _ := time.Parse("02-01-2006", data.ImprovementDate)
	tempT, _ := time.Parse("15:04:05", data.ImprovementTime)
	fmt.Println(tempD)

	if _, err = d.stmt[insertNewImprovementData].ExecContext(ctx,
		data.ImprovementID,
		data.ImprovementMemberID,
		data.ImprovementMemberName,
		data.ImprovementJournalID,
		data.ImprovementSymptomID,
		data.ImprovementRemedyID,
		data.ImprovementRemedyName,
		tempD,
		tempT.Format("15:04:05"),
	); err != nil {
		return errors.Wrap(err, "[DATA][InsertNewImprovementData]")
	}

	return err
}

// GetQImprovementlDataByMemberID ...
func (d Data) GetQImprovementlDataByMemberID(ctx context.Context, memberID string) ([]qjournalEntity.ImprovementData, error) {
	var (
		rows  *sqlx.Rows
		data  qjournalEntity.ImprovementData
		datas []qjournalEntity.ImprovementData
		err   error
	)

	d.checkConnection(ctx)

	rows, err = d.stmt[getQImprovementDataByMemberID].QueryxContext(ctx, memberID)
	for rows.Next() {
		if err = rows.StructScan(&data); err != nil {
			return datas, errors.Wrap(err, "[DATA][GetQImprovementlDataByMemberID]")
		}
		datas = append(datas, data)
	}
	defer rows.Close()

	return datas, err
}

// GetQImprovementlDataByJournalID ...
func (d Data) GetQImprovementlDataByJournalIDAndMemberID(ctx context.Context, journalID string, memberID string) ([]qjournalEntity.ImprovementData, error) {
	var (
		rows  *sqlx.Rows
		data  qjournalEntity.ImprovementData
		datas []qjournalEntity.ImprovementData
		err   error
	)

	d.checkConnection(ctx)

	rows, err = d.stmt[getQImprovementlDataByJournalIDAndMemberID].QueryxContext(ctx, journalID, memberID)
	for rows.Next() {
		if err = rows.StructScan(&data); err != nil {
			return datas, errors.Wrap(err, "[DATA][GetQImprovementlDataByJournalIDAndMemberID]")
		}
		datas = append(datas, data)
	}
	defer rows.Close()

	return datas, err
}
