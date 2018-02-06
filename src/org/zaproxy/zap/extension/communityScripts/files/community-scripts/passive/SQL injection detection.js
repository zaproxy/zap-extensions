// Made by kurobeats@yahoo.co.jp, regex shamelessly ripped from SQLMap project errors

function scan(ps, msg, src)
{
    url = msg.getRequestHeader().getURI().toString();
    body = msg.getResponseBody().toString()
    alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    alertReliability = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    alertTitle = ["MySQL error Disclosed (script)",
		  "Postgresql error Disclosed (script)",
		  "MSSQL error Disclosed (script)",
		  "Microsoft Access error Disclosed (script)",
		  "Oracle error Disclosed (script)",
		  "IBM DB2 error Disclosed (script)",
		  "Informix error Disclosed (script)",
		  "Firebird error Disclosed (script)",
		  "SQLite error Disclosed (script)",
		  "SAP DB error Disclosed (script)",
		  "Sybase error Disclosed (script)",
		  "Ingress error Disclosed (script)",
		  "Frontbase error Disclosed (script)",
		  "HSQLDB error Disclosed (script)",
		  ""]
    alertDesc = ["A MySQL error was discovered.",
		 "A Postgresql error was discovered.",
		 "A MSSQL error was discovered.",
		 "A Microsoft Access error was discovered.",
		 "An Oracle error was discovered.",
		 "An IBM DB2 error was discovered.",
		 "An Informix error was discovered.",
		 "A Firebird error was discovered.",
		 "An SQLite error was discovered",
		 "A SAP DB error was discovered",
		 "A Sybase error was discovered",
		 "An Ingress error was discovered",
		 "A Frontbase error was discovered",
		 "A HSQLDB error was discovered",
		""]
    alertSolution = ["Ensure proper sanitisation is done on the server side, or don't. I don't care.",
		    ""]
    cweId = [0,1]
    wascId = [0,1]

    mysql = /(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\.|com\.mysql\.jdbc\.exceptions)/g
    postgresql = /(PostgreSQL.*ERROR|Warning.*\Wpg_.*|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s\ssyntax error at or near)/g
    mssql = /(Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\s\S]Exception.*\WSystem\.Data\.SqlClient\.|[\s\S]Exception.*\WRoadhouse\.Cms\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})/g
    msaccess = /(Microsoft Access (\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)/g
    oracle = /(\bORA-\d{5}|Oracle error|Oracle.*Driver|Warning.*\Woci_.*|Warning.*\Wora_.*)/g
    ibmdb2 = /(CLI Driver.*DB2|DB2 SQL error|\bdb2_\w+\(|SQLSTATE.+SQLCODE)/g
    informix = /(Exception.*Informix)/g
    firebird = /(Dynamic SQL Error|Warning.*ibase_.*)/g
    sqlite = /(SQLite\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\[SQLITE_ERROR\])/g
	sapdb = /(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)/g
	sybase = /(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\.sybase\.jdbc)/g
	ingress = /(Warning.*ingres_|Ingres SQLSTATE|Ingres\W.*Driver)/g
	frontbase = /(Exception (condition )?\d+. Transaction rollback.)/g
	hsqldb = /(org\.hsqldb\.jdbc|Unexpected end of command in statement \[|Unexpected token.*in statement \[)/g

	if (mysql.test(body))
	  {
	    mysql.lastIndex = 0
	    var foundmysql = []
            while (comm = mysql.exec(body))
	      {
               foundmysql.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundmysql.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (postgresql.test(body))
	  {
	    postgresql.lastIndex = 0
	    var foundpostgresql = []
            while (comm = postgresql.exec(body))
	      {
               foundpostgresql.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[1], alertDesc[1], url, '', '', foundpostgresql.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (mssql.test(body))
	  {
	    mssql.lastIndex = 0
	    var foundmssql = []
            while (comm = mssql.exec(body))
	      {
               foundmssql.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[2], alertDesc[2], url, '', '', foundmssql.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (msaccess.test(body))
	  {
	    msaccess.lastIndex = 0
	    var foundmsaccess = []
            while (comm = msaccess.exec(body))
	      {
               foundmsaccess.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[3], alertDesc[3], url, '', '', foundmsaccess.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (oracle.test(body))
	  {
	    oracle.lastIndex = 0
	    var foundoracle = []
            while (comm = oracle.exec(body))
	      {
               foundoracle.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[4], alertDesc[4], url, '', '', foundoracle.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (ibmdb2.test(body))
	  {
	    ibmdb2.lastIndex = 0
	    var foundibmdb2 = []
            while (comm = ibmdb2.exec(body))
	      {
               foundibmdb2.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[5], alertDesc[5], url, '', '', foundibmdb2.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (informix.test(body))
	  {
	    informix.lastIndex = 0
	    var foundinformix = []
            while (comm = informix.exec(body))
	      {
               foundinformix.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[6], alertDesc[6], url, '', '', foundinformix.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (firebird.test(body))
	  {
	    firebird.lastIndex = 0
	    var foundfirebird = []
            while (comm = firebird.exec(body))
	      {
               foundfirebird.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[7], alertDesc[7], url, '', '', foundfirebird.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sqlite.test(body))
	  {
	    sqlite.lastIndex = 0
	    var foundsqlite = []
            while (comm = sqlite.exec(body))
	      {
               foundsqlite.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertReliability[1], alertTitle[8], alertDesc[8], url, '', '', foundsqlite.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sapdb.test(body))
	  {
	    sapdb.lastIndex = 0
	    var foundvbull = []
            while (comm = sapdb.exec(body))
	      {
               foundsapdb.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[9], alertDesc[9], url, '', '', foundsapdb.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sybase.test(body))
	  {
	    sybase.lastIndex = 0
	    var foundsybase = []
            while (comm = sybase.exec(body))
	      {
               foundsybase.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[10], alertDesc[10], url, '', '', foundsybase.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (ingress.test(body))
	  {
	    ingress.lastIndex = 0
	    var foundingress = []
            while (comm = ingress.exec(body))
	      {
               foundingress.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[11], alertDesc[11], url, '', '', foundingress.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (frontbase.test(body))
	  {
	    frontbase.lastIndex = 0
	    var foundfrontbase = []
            while (comm = frontbase.exec(body))
	      {
               foundfrontbase.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[12], alertDesc[12], url, '', '', foundfrontbase.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (hsqldb.test(body))
	  {
	    hsqldb.lastIndex = 0
	    var foundhsqldb = []
            while (comm = hsqldb.exec(body))
	      {
               foundhsqldb.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[13], alertDesc[13], url, '', '', foundhsqldb.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
