package clickhouse_test

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	dt "github.com/ory/dockertest/v3"
	"github.com/ildus/usql/drivers/clickhouse"
	"github.com/ildus/usql/drivers/metadata"
	"github.com/yookoala/realpath"
)

// db is the database connection.
var db struct {
	db  *sql.DB
	res *dt.Resource
	r   metadata.BasicReader
}

func TestMain(m *testing.M) {
	cleanup := flag.Bool("cleanup", true, "cleanup when finished")
	flag.Parse()
	code, err := doMain(m, *cleanup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func doMain(m *testing.M, cleanup bool) (int, error) {
	dir, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	dir, err = realpath.Realpath(dir)
	if err != nil {
		return 0, err
	}
	pool, err := dt.NewPool("")
	if err != nil {
		return 0, fmt.Errorf("could not connect to docker: %w", err)
	}
	db.res, err = pool.RunWithOptions(&dt.RunOptions{
		Repository: "clickhouse/clickhouse-server",
		Tag:        "22.7",
		Mounts:     []string{filepath.Join(dir, "testdata") + ":/docker-entrypoint-initdb.d"},
	})
	if err != nil {
		return 0, fmt.Errorf("unable to run: %w", err)
	}
	if cleanup {
		defer func() {
			if err := pool.Purge(db.res); err != nil {
				fmt.Fprintf(os.Stderr, "error: could not purge resoure: %v\n", err)
			}
		}()
	}
	// exponential backoff-retry, because the application in the container
	// might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		port := db.res.GetPort("9000/tcp")
		var err error
		if db.db, err = sql.Open("clickhouse", fmt.Sprintf("clickhouse://127.0.0.1:%s", port)); err != nil {
			return err
		}
		return db.db.Ping()
	}); err != nil {
		return 0, fmt.Errorf("unable to open database: %w", err)
	}
	db.r = clickhouse.NewMetadataReader(db.db).(metadata.BasicReader)
	code := m.Run()
	return code, nil
}

func TestSchemas(t *testing.T) {
	res, err := db.r.Schemas(metadata.Filter{WithSystem: true})
	if err != nil {
		t.Fatalf("could not read schemas: %v", err)
	}
	checkNames(t, "schema", res, "default", "system", "tutorial", "tutorial_unexpected", "INFORMATION_SCHEMA", "information_schema")
}

func TestTables(t *testing.T) {
	res, err := db.r.Tables(metadata.Filter{
		Schema: "tutorial",
		Types:  []string{"BASE TABLE", "TABLE", "VIEW"},
	})
	if err != nil {
		t.Fatalf("could not read tables: %v", err)
	}
	checkNames(t, "table", res, "hits_v1", "visits_v1")
}

func TestFunctions(t *testing.T) {
	r := clickhouse.NewMetadataReader(db.db).(metadata.FunctionReader)
	res, err := r.Functions(metadata.Filter{Schema: "tutorial"})
	if err != nil {
		t.Fatalf("could not read functions: %v", err)
	}
	checkNames(t, "function", res, funcNames()...)
}

func TestColumns(t *testing.T) {
	res, err := db.r.Columns(metadata.Filter{
		Schema: "tutorial",
		Parent: "hits_v1",
	})
	if err != nil {
		log.Fatalf("could not read columns: %v", err)
	}
	checkNames(t, "column", res, colNames()...)
}

func checkNames(t *testing.T, typ string, res interface{ Next() bool }, exp ...string) {
	n := make(map[string]bool)
	for _, s := range exp {
		n[s] = true
	}
	names := make(map[string]bool)
	for res.Next() {
		name := getName(res)
		if _, ok := names[name]; ok {
			t.Errorf("already declared %s %q", typ, name)
		}
		names[name] = true
	}
	for name := range n {
		if _, ok := names[name]; !ok {
			t.Errorf("missing %s %q", typ, name)
		}
	}
	for name := range names {
		if _, ok := n[name]; !ok {
			t.Errorf("unexpected %s %q", typ, name)
		}
	}
}

func getName(res interface{}) string {
	switch x := res.(type) {
	case *metadata.SchemaSet:
		return x.Get().Schema
	case *metadata.TableSet:
		return x.Get().Name
	case *metadata.FunctionSet:
		return x.Get().Name
	case *metadata.ColumnSet:
		return x.Get().Name
	}
	panic(fmt.Sprintf("unknown type %T", res))
}

func funcNames() []string {
	return []string{
		"BIT_AND",
		"BIT_OR",
		"BIT_XOR",
		"CAST",
		"CHARACTER_LENGTH",
		"CHAR_LENGTH",
		"COVAR_POP",
		"COVAR_SAMP",
		"CRC32",
		"CRC32IEEE",
		"CRC64",
		"DATABASE",
		"DATE",
		"DAY",
		"DAYOFMONTH",
		"DAYOFWEEK",
		"DAYOFYEAR",
		"FQDN",
		"FROM_BASE64",
		"FROM_UNIXTIME",
		"HOUR",
		"INET6_ATON",
		"INET6_NTOA",
		"INET_ATON",
		"INET_NTOA",
		"IPv4CIDRToRange",
		"IPv4NumToString",
		"IPv4NumToStringClassC",
		"IPv4StringToNum",
		"IPv4StringToNumOrDefault",
		"IPv4StringToNumOrNull",
		"IPv4ToIPv6",
		"IPv6CIDRToRange",
		"IPv6NumToString",
		"IPv6StringToNum",
		"IPv6StringToNumOrDefault",
		"IPv6StringToNumOrNull",
		"JSONExtract",
		"JSONExtractArrayRaw",
		"JSONExtractBool",
		"JSONExtractFloat",
		"JSONExtractInt",
		"JSONExtractKeys",
		"JSONExtractKeysAndValues",
		"JSONExtractKeysAndValuesRaw",
		"JSONExtractRaw",
		"JSONExtractString",
		"JSONExtractUInt",
		"JSONHas",
		"JSONKey",
		"JSONLength",
		"JSONType",
		"JSON_EXISTS",
		"JSON_QUERY",
		"JSON_VALUE",
		"L1Distance",
		"L1Norm",
		"L1Normalize",
		"L2Distance",
		"L2Norm",
		"L2Normalize",
		"L2SquaredDistance",
		"L2SquaredNorm",
		"LAST_DAY",
		"LinfDistance",
		"LinfNorm",
		"LinfNormalize",
		"LpDistance",
		"LpNorm",
		"LpNormalize",
		"MACNumToString",
		"MACStringToNum",
		"MACStringToOUI",
		"MD4",
		"MD5",
		"MINUTE",
		"MONTH",
		"QUARTER",
		"REGEXP_MATCHES",
		"REGEXP_REPLACE",
		"SECOND",
		"SHA1",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"STDDEV_POP",
		"STDDEV_SAMP",
		"SVG",
		"TO_BASE64",
		"URLHash",
		"URLHierarchy",
		"URLPathHierarchy",
		"UUIDNumToString",
		"UUIDStringToNum",
		"VAR_POP",
		"VAR_SAMP",
		"YEAR",
		"_CAST",
		"__bitBoolMaskAnd",
		"__bitBoolMaskOr",
		"__bitSwapLastTwo",
		"__bitWrapperFunc",
		"__getScalar",
		"abs",
		"accurateCast",
		"accurateCastOrDefault",
		"accurateCastOrNull",
		"accurate_Cast",
		"accurate_CastOrNull",
		"acos",
		"acosh",
		"addDays",
		"addHours",
		"addMicroseconds",
		"addMilliseconds",
		"addMinutes",
		"addMonths",
		"addNanoseconds",
		"addQuarters",
		"addSeconds",
		"addWeeks",
		"addYears",
		"addressToLine",
		"addressToLineWithInlines",
		"addressToSymbol",
		"aes_decrypt_mysql",
		"aes_encrypt_mysql",
		"aggThrow",
		"alphaTokens",
		"and",
		"any",
		"anyHeavy",
		"anyLast",
		"appendTrailingCharIfAbsent",
		"argMax",
		"argMin",
		"array",
		"arrayAUC",
		"arrayAll",
		"arrayAvg",
		"arrayCompact",
		"arrayConcat",
		"arrayCount",
		"arrayCumSum",
		"arrayCumSumNonNegative",
		"arrayDifference",
		"arrayDistinct",
		"arrayElement",
		"arrayEnumerate",
		"arrayEnumerateDense",
		"arrayEnumerateDenseRanked",
		"arrayEnumerateUniq",
		"arrayEnumerateUniqRanked",
		"arrayExists",
		"arrayFill",
		"arrayFilter",
		"arrayFirst",
		"arrayFirstIndex",
		"arrayFirstOrNull",
		"arrayFlatten",
		"arrayIntersect",
		"arrayJoin",
		"arrayLast",
		"arrayLastIndex",
		"arrayLastOrNull",
		"arrayMap",
		"arrayMax",
		"arrayMin",
		"arrayPopBack",
		"arrayPopFront",
		"arrayProduct",
		"arrayPushBack",
		"arrayPushFront",
		"arrayReduce",
		"arrayReduceInRanges",
		"arrayResize",
		"arrayReverse",
		"arrayReverseFill",
		"arrayReverseSort",
		"arrayReverseSplit",
		"arraySlice",
		"arraySort",
		"arraySplit",
		"arrayStringConcat",
		"arraySum",
		"arrayUniq",
		"arrayWithConstant",
		"arrayZip",
		"asin",
		"asinh",
		"assumeNotNull",
		"atan",
		"atan2",
		"atanh",
		"avg",
		"avgWeighted",
		"bar",
		"base58Decode",
		"base58Encode",
		"base64Decode",
		"base64Encode",
		"basename",
		"bin",
		"bitAnd",
		"bitCount",
		"bitHammingDistance",
		"bitNot",
		"bitOr",
		"bitPositionsToArray",
		"bitRotateLeft",
		"bitRotateRight",
		"bitShiftLeft",
		"bitShiftRight",
		"bitSlice",
		"bitTest",
		"bitTestAll",
		"bitTestAny",
		"bitXor",
		"bitmapAnd",
		"bitmapAndCardinality",
		"bitmapAndnot",
		"bitmapAndnotCardinality",
		"bitmapBuild",
		"bitmapCardinality",
		"bitmapContains",
		"bitmapHasAll",
		"bitmapHasAny",
		"bitmapMax",
		"bitmapMin",
		"bitmapOr",
		"bitmapOrCardinality",
		"bitmapSubsetInRange",
		"bitmapSubsetLimit",
		"bitmapToArray",
		"bitmapTransform",
		"bitmapXor",
		"bitmapXorCardinality",
		"bitmaskToArray",
		"bitmaskToList",
		"blockNumber",
		"blockSerializedSize",
		"blockSize",
		"boundingRatio",
		"buildId",
		"byteSize",
		"caseWithExpr",
		"caseWithExpression",
		"caseWithoutExpr",
		"caseWithoutExpression",
		"categoricalInformationValue",
		"cbrt",
		"ceil",
		"ceiling",
		"char",
		"cityHash64",
		"coalesce",
		"concat",
		"concatAssumeInjective",
		"connectionId",
		"connection_id",
		"contingency",
		"convertCharset",
		"corr",
		"corrStable",
		"cos",
		"cosh",
		"cosineDistance",
		"count",
		"countDigits",
		"countEqual",
		"countMatches",
		"countMatchesCaseInsensitive",
		"countSubstrings",
		"countSubstringsCaseInsensitive",
		"countSubstringsCaseInsensitiveUTF8",
		"covarPop",
		"covarPopStable",
		"covarSamp",
		"covarSampStable",
		"cramersV",
		"cramersVBiasCorrected",
		"currentDatabase",
		"currentProfiles",
		"currentRoles",
		"currentUser",
		"cutFragment",
		"cutIPv6",
		"cutQueryString",
		"cutQueryStringAndFragment",
		"cutToFirstSignificantSubdomain",
		"cutToFirstSignificantSubdomainCustom",
		"cutToFirstSignificantSubdomainCustomWithWWW",
		"cutToFirstSignificantSubdomainWithWWW",
		"cutURLParameter",
		"cutWWW",
		"dateDiff",
		"dateName",
		"dateTime64ToSnowflake",
		"dateTimeToSnowflake",
		"dateTrunc",
		"date_trunc",
		"decodeURLComponent",
		"decodeURLFormComponent",
		"decodeXMLComponent",
		"decrypt",
		"defaultProfiles",
		"defaultRoles",
		"defaultValueOfArgumentType",
		"defaultValueOfTypeName",
		"degrees",
		"deltaSum",
		"deltaSumTimestamp",
		"demangle",
		"dense_rank",
		"detectCharset",
		"detectLanguage",
		"detectLanguageMixed",
		"detectLanguageUnknown",
		"detectProgrammingLanguage",
		"detectTonality",
		"dictGet",
		"dictGetChildren",
		"dictGetDate",
		"dictGetDateOrDefault",
		"dictGetDateTime",
		"dictGetDateTimeOrDefault",
		"dictGetDescendants",
		"dictGetFloat32",
		"dictGetFloat32OrDefault",
		"dictGetFloat64",
		"dictGetFloat64OrDefault",
		"dictGetHierarchy",
		"dictGetInt16",
		"dictGetInt16OrDefault",
		"dictGetInt32",
		"dictGetInt32OrDefault",
		"dictGetInt64",
		"dictGetInt64OrDefault",
		"dictGetInt8",
		"dictGetInt8OrDefault",
		"dictGetOrDefault",
		"dictGetOrNull",
		"dictGetString",
		"dictGetStringOrDefault",
		"dictGetUInt16",
		"dictGetUInt16OrDefault",
		"dictGetUInt32",
		"dictGetUInt32OrDefault",
		"dictGetUInt64",
		"dictGetUInt64OrDefault",
		"dictGetUInt8",
		"dictGetUInt8OrDefault",
		"dictGetUUID",
		"dictGetUUIDOrDefault",
		"dictHas",
		"dictIsIn",
		"distanceL1",
		"distanceL2",
		"distanceL2Squared",
		"distanceLinf",
		"distanceLp",
		"divide",
		"domain",
		"domainWithoutWWW",
		"dotProduct",
		"dumpColumnStructure",
		"e",
		"empty",
		"emptyArrayDate",
		"emptyArrayDateTime",
		"emptyArrayFloat32",
		"emptyArrayFloat64",
		"emptyArrayInt16",
		"emptyArrayInt32",
		"emptyArrayInt64",
		"emptyArrayInt8",
		"emptyArrayString",
		"emptyArrayToSingle",
		"emptyArrayUInt16",
		"emptyArrayUInt32",
		"emptyArrayUInt64",
		"emptyArrayUInt8",
		"enabledProfiles",
		"enabledRoles",
		"encodeURLComponent",
		"encodeURLFormComponent",
		"encodeXMLComponent",
		"encrypt",
		"endsWith",
		"entropy",
		"equals",
		"erf",
		"erfc",
		"errorCodeToName",
		"evalMLMethod",
		"exp",
		"exp10",
		"exp2",
		"exponentialMovingAverage",
		"exponentialTimeDecayedAvg",
		"exponentialTimeDecayedCount",
		"exponentialTimeDecayedMax",
		"exponentialTimeDecayedSum",
		"extract",
		"extractAll",
		"extractAllGroups",
		"extractAllGroupsHorizontal",
		"extractAllGroupsVertical",
		"extractGroups",
		"extractTextFromHTML",
		"extractURLParameter",
		"extractURLParameterNames",
		"extractURLParameters",
		"farmFingerprint64",
		"farmHash64",
		"file",
		"filesystemAvailable",
		"filesystemCapacity",
		"filesystemFree",
		"finalizeAggregation",
		"firstSignificantSubdomain",
		"firstSignificantSubdomainCustom",
		"first_value",
		"flatten",
		"flattenTuple",
		"floor",
		"format",
		"formatDateTime",
		"formatReadableQuantity",
		"formatReadableSize",
		"formatReadableTimeDelta",
		"formatRow",
		"formatRowNoNewline",
		"fragment",
		"fromModifiedJulianDay",
		"fromModifiedJulianDayOrNull",
		"fromUnixTimestamp",
		"fromUnixTimestamp64Micro",
		"fromUnixTimestamp64Milli",
		"fromUnixTimestamp64Nano",
		"fullHostName",
		"fuzzBits",
		"gccMurmurHash",
		"gcd",
		"generateUUIDv4",
		"geoDistance",
		"geoToH3",
		"geoToS2",
		"geohashDecode",
		"geohashEncode",
		"geohashesInBox",
		"getMacro",
		"getOSKernelVersion",
		"getServerPort",
		"getSetting",
		"getSizeOfEnumType",
		"getTypeSerializationStreams",
		"globalIn",
		"globalInIgnoreSet",
		"globalNotIn",
		"globalNotInIgnoreSet",
		"globalNotNullIn",
		"globalNotNullInIgnoreSet",
		"globalNullIn",
		"globalNullInIgnoreSet",
		"globalVariable",
		"greatCircleAngle",
		"greatCircleDistance",
		"greater",
		"greaterOrEquals",
		"greatest",
		"groupArray",
		"groupArrayInsertAt",
		"groupArrayMovingAvg",
		"groupArrayMovingSum",
		"groupArraySample",
		"groupBitAnd",
		"groupBitOr",
		"groupBitXor",
		"groupBitmap",
		"groupBitmapAnd",
		"groupBitmapOr",
		"groupBitmapXor",
		"groupUniqArray",
		"h3CellAreaM2",
		"h3CellAreaRads2",
		"h3Distance",
		"h3EdgeAngle",
		"h3EdgeLengthKm",
		"h3EdgeLengthM",
		"h3ExactEdgeLengthKm",
		"h3ExactEdgeLengthM",
		"h3ExactEdgeLengthRads",
		"h3GetBaseCell",
		"h3GetDestinationIndexFromUnidirectionalEdge",
		"h3GetFaces",
		"h3GetIndexesFromUnidirectionalEdge",
		"h3GetOriginIndexFromUnidirectionalEdge",
		"h3GetPentagonIndexes",
		"h3GetRes0Indexes",
		"h3GetResolution",
		"h3GetUnidirectionalEdge",
		"h3GetUnidirectionalEdgeBoundary",
		"h3GetUnidirectionalEdgesFromHexagon",
		"h3HexAreaKm2",
		"h3HexAreaM2",
		"h3HexRing",
		"h3IndexesAreNeighbors",
		"h3IsPentagon",
		"h3IsResClassIII",
		"h3IsValid",
		"h3Line",
		"h3NumHexagons",
		"h3PointDistKm",
		"h3PointDistM",
		"h3PointDistRads",
		"h3ToCenterChild",
		"h3ToChildren",
		"h3ToGeo",
		"h3ToGeoBoundary",
		"h3ToParent",
		"h3ToString",
		"h3UnidirectionalEdgeIsValid",
		"h3kRing",
		"halfMD5",
		"has",
		"hasAll",
		"hasAny",
		"hasColumnInTable",
		"hasSubstr",
		"hasThreadFuzzer",
		"hasToken",
		"hasTokenCaseInsensitive",
		"hashid",
		"hex",
		"histogram",
		"hiveHash",
		"hop",
		"hopEnd",
		"hopStart",
		"hostName",
		"hostname",
		"hypot",
		"identity",
		"if",
		"ifNotFinite",
		"ifNull",
		"ignore",
		"ilike",
		"in",
		"inIgnoreSet",
		"indexHint",
		"indexOf",
		"initialQueryID",
		"initial_query_id",
		"initializeAggregation",
		"intDiv",
		"intDivOrZero",
		"intExp10",
		"intExp2",
		"intHash32",
		"intHash64",
		"intervalLengthSum",
		"isConstant",
		"isDecimalOverflow",
		"isFinite",
		"isIPAddressInRange",
		"isIPv4String",
		"isIPv6String",
		"isInfinite",
		"isNaN",
		"isNotNull",
		"isNull",
		"isNullable",
		"isValidJSON",
		"isValidUTF8",
		"isZeroOrNull",
		"javaHash",
		"javaHashUTF16LE",
		"joinGet",
		"joinGetOrNull",
		"jumpConsistentHash",
		"kostikConsistentHash",
		"kurtPop",
		"kurtSamp",
		"lagInFrame",
		"last_value",
		"lcase",
		"lcm",
		"leadInFrame",
		"least",
		"left",
		"leftPad",
		"leftPadUTF8",
		"leftUTF8",
		"lemmatize",
		"length",
		"lengthUTF8",
		"less",
		"lessOrEquals",
		"lgamma",
		"like",
		"ln",
		"locate",
		"log",
		"log10",
		"log1p",
		"log2",
		"logTrace",
		"lowCardinalityIndices",
		"lowCardinalityKeys",
		"lower",
		"lowerUTF8",
		"lpad",
		"makeDate",
		"makeDate32",
		"makeDateTime",
		"makeDateTime64",
		"mannWhitneyUTest",
		"map",
		"mapAdd",
		"mapApply",
		"mapContains",
		"mapContainsKeyLike",
		"mapExtractKeyLike",
		"mapFilter",
		"mapKeys",
		"mapPopulateSeries",
		"mapSubtract",
		"mapUpdate",
		"mapValues",
		"match",
		"materialize",
		"max",
		"max2",
		"maxIntersections",
		"maxIntersectionsPosition",
		"maxMap",
		"maxMappedArrays",
		"meanZTest",
		"median",
		"medianBFloat16",
		"medianBFloat16Weighted",
		"medianDeterministic",
		"medianExact",
		"medianExactHigh",
		"medianExactLow",
		"medianExactWeighted",
		"medianTDigest",
		"medianTDigestWeighted",
		"medianTiming",
		"medianTimingWeighted",
		"meiliMatch",
		"metroHash64",
		"mid",
		"min",
		"min2",
		"minMap",
		"minMappedArrays",
		"minSampleSizeContinous",
		"minSampleSizeConversion",
		"minus",
		"mod",
		"modelEvaluate",
		"modulo",
		"moduloLegacy",
		"moduloOrZero",
		"monthName",
		"multiFuzzyMatchAllIndices",
		"multiFuzzyMatchAny",
		"multiFuzzyMatchAnyIndex",
		"multiIf",
		"multiMatchAllIndices",
		"multiMatchAny",
		"multiMatchAnyIndex",
		"multiSearchAllPositions",
		"multiSearchAllPositionsCaseInsensitive",
		"multiSearchAllPositionsCaseInsensitiveUTF8",
		"multiSearchAllPositionsUTF8",
		"multiSearchAny",
		"multiSearchAnyCaseInsensitive",
		"multiSearchAnyCaseInsensitiveUTF8",
		"multiSearchAnyUTF8",
		"multiSearchFirstIndex",
		"multiSearchFirstIndexCaseInsensitive",
		"multiSearchFirstIndexCaseInsensitiveUTF8",
		"multiSearchFirstIndexUTF8",
		"multiSearchFirstPosition",
		"multiSearchFirstPositionCaseInsensitive",
		"multiSearchFirstPositionCaseInsensitiveUTF8",
		"multiSearchFirstPositionUTF8",
		"multiply",
		"murmurHash2_32",
		"murmurHash2_64",
		"murmurHash3_128",
		"murmurHash3_32",
		"murmurHash3_64",
		"negate",
		"neighbor",
		"netloc",
		"ngramDistance",
		"ngramDistanceCaseInsensitive",
		"ngramDistanceCaseInsensitiveUTF8",
		"ngramDistanceUTF8",
		"ngramMinHash",
		"ngramMinHashArg",
		"ngramMinHashArgCaseInsensitive",
		"ngramMinHashArgCaseInsensitiveUTF8",
		"ngramMinHashArgUTF8",
		"ngramMinHashCaseInsensitive",
		"ngramMinHashCaseInsensitiveUTF8",
		"ngramMinHashUTF8",
		"ngramSearch",
		"ngramSearchCaseInsensitive",
		"ngramSearchCaseInsensitiveUTF8",
		"ngramSearchUTF8",
		"ngramSimHash",
		"ngramSimHashCaseInsensitive",
		"ngramSimHashCaseInsensitiveUTF8",
		"ngramSimHashUTF8",
		"ngrams",
		"nonNegativeDerivative",
		"normL1",
		"normL2",
		"normL2Squared",
		"normLinf",
		"normLp",
		"normalizeL1",
		"normalizeL2",
		"normalizeLinf",
		"normalizeLp",
		"normalizeQuery",
		"normalizeQueryKeepNames",
		"normalizeUTF8NFC",
		"normalizeUTF8NFD",
		"normalizeUTF8NFKC",
		"normalizeUTF8NFKD",
		"normalizedQueryHash",
		"normalizedQueryHashKeepNames",
		"not",
		"notEmpty",
		"notEquals",
		"notILike",
		"notIn",
		"notInIgnoreSet",
		"notLike",
		"notNullIn",
		"notNullInIgnoreSet",
		"nothing",
		"now",
		"now64",
		"nth_value",
		"nullIf",
		"nullIn",
		"nullInIgnoreSet",
		"or",
		"parseDateTime32BestEffort",
		"parseDateTime32BestEffortOrNull",
		"parseDateTime32BestEffortOrZero",
		"parseDateTime64BestEffort",
		"parseDateTime64BestEffortOrNull",
		"parseDateTime64BestEffortOrZero",
		"parseDateTimeBestEffort",
		"parseDateTimeBestEffortOrNull",
		"parseDateTimeBestEffortOrZero",
		"parseDateTimeBestEffortUS",
		"parseDateTimeBestEffortUSOrNull",
		"parseDateTimeBestEffortUSOrZero",
		"parseTimeDelta",
		"partitionId",
		"path",
		"pathFull",
		"pi",
		"plus",
		"pointInEllipses",
		"pointInPolygon",
		"polygonAreaCartesian",
		"polygonAreaSpherical",
		"polygonConvexHullCartesian",
		"polygonPerimeterCartesian",
		"polygonPerimeterSpherical",
		"polygonsDistanceCartesian",
		"polygonsDistanceSpherical",
		"polygonsEqualsCartesian",
		"polygonsIntersectionCartesian",
		"polygonsIntersectionSpherical",
		"polygonsSymDifferenceCartesian",
		"polygonsSymDifferenceSpherical",
		"polygonsUnionCartesian",
		"polygonsUnionSpherical",
		"polygonsWithinCartesian",
		"polygonsWithinSpherical",
		"port",
		"position",
		"positionCaseInsensitive",
		"positionCaseInsensitiveUTF8",
		"positionUTF8",
		"pow",
		"power",
		"proportionsZTest",
		"protocol",
		"quantile",
		"quantileBFloat16",
		"quantileBFloat16Weighted",
		"quantileDeterministic",
		"quantileExact",
		"quantileExactExclusive",
		"quantileExactHigh",
		"quantileExactInclusive",
		"quantileExactLow",
		"quantileExactWeighted",
		"quantileTDigest",
		"quantileTDigestWeighted",
		"quantileTiming",
		"quantileTimingWeighted",
		"quantiles",
		"quantilesBFloat16",
		"quantilesBFloat16Weighted",
		"quantilesDeterministic",
		"quantilesExact",
		"quantilesExactExclusive",
		"quantilesExactHigh",
		"quantilesExactInclusive",
		"quantilesExactLow",
		"quantilesExactWeighted",
		"quantilesTDigest",
		"quantilesTDigestWeighted",
		"quantilesTiming",
		"quantilesTimingWeighted",
		"queryID",
		"queryString",
		"queryStringAndFragment",
		"query_id",
		"radians",
		"rand",
		"rand32",
		"rand64",
		"randConstant",
		"randomFixedString",
		"randomPrintableASCII",
		"randomString",
		"randomStringUTF8",
		"range",
		"rank",
		"rankCorr",
		"readWKTMultiPolygon",
		"readWKTPoint",
		"readWKTPolygon",
		"readWKTRing",
		"regexpQuoteMeta",
		"regionHierarchy",
		"regionIn",
		"regionToArea",
		"regionToCity",
		"regionToContinent",
		"regionToCountry",
		"regionToDistrict",
		"regionToName",
		"regionToPopulation",
		"regionToTopContinent",
		"reinterpret",
		"reinterpretAsDate",
		"reinterpretAsDateTime",
		"reinterpretAsFixedString",
		"reinterpretAsFloat32",
		"reinterpretAsFloat64",
		"reinterpretAsInt128",
		"reinterpretAsInt16",
		"reinterpretAsInt256",
		"reinterpretAsInt32",
		"reinterpretAsInt64",
		"reinterpretAsInt8",
		"reinterpretAsString",
		"reinterpretAsUInt128",
		"reinterpretAsUInt16",
		"reinterpretAsUInt256",
		"reinterpretAsUInt32",
		"reinterpretAsUInt64",
		"reinterpretAsUInt8",
		"reinterpretAsUUID",
		"repeat",
		"replace",
		"replaceAll",
		"replaceOne",
		"replaceRegexpAll",
		"replaceRegexpOne",
		"replicate",
		"retention",
		"reverse",
		"reverseUTF8",
		"revision",
		"right",
		"rightPad",
		"rightPadUTF8",
		"rightUTF8",
		"round",
		"roundAge",
		"roundBankers",
		"roundDown",
		"roundDuration",
		"roundToExp2",
		"rowNumberInAllBlocks",
		"rowNumberInBlock",
		"row_number",
		"rpad",
		"runningAccumulate",
		"runningConcurrency",
		"runningDifference",
		"runningDifferenceStartingWithFirstValue",
		"s2CapContains",
		"s2CapUnion",
		"s2CellsIntersect",
		"s2GetNeighbors",
		"s2RectAdd",
		"s2RectContains",
		"s2RectIntersection",
		"s2RectUnion",
		"s2ToGeo",
		"scalarProduct",
		"sequenceCount",
		"sequenceMatch",
		"sequenceNextNode",
		"serverUUID",
		"shardCount",
		"shardNum",
		"showCertificate",
		"sigmoid",
		"sign",
		"simpleJSONExtractBool",
		"simpleJSONExtractFloat",
		"simpleJSONExtractInt",
		"simpleJSONExtractRaw",
		"simpleJSONExtractString",
		"simpleJSONExtractUInt",
		"simpleJSONHas",
		"simpleLinearRegression",
		"sin",
		"singleValueOrNull",
		"sinh",
		"sipHash128",
		"sipHash64",
		"skewPop",
		"skewSamp",
		"sleep",
		"sleepEachRow",
		"snowflakeToDateTime",
		"snowflakeToDateTime64",
		"sparkbar",
		"splitByChar",
		"splitByNonAlpha",
		"splitByRegexp",
		"splitByString",
		"splitByWhitespace",
		"sqrt",
		"startsWith",
		"stddevPop",
		"stddevPopStable",
		"stddevSamp",
		"stddevSampStable",
		"stem",
		"stochasticLinearRegression",
		"stochasticLogisticRegression",
		"stringToH3",
		"studentTTest",
		"subBitmap",
		"substr",
		"substring",
		"substringUTF8",
		"subtractDays",
		"subtractHours",
		"subtractMicroseconds",
		"subtractMilliseconds",
		"subtractMinutes",
		"subtractMonths",
		"subtractNanoseconds",
		"subtractQuarters",
		"subtractSeconds",
		"subtractWeeks",
		"subtractYears",
		"sum",
		"sumCount",
		"sumKahan",
		"sumMap",
		"sumMapFiltered",
		"sumMapFilteredWithOverflow",
		"sumMapWithOverflow",
		"sumMappedArrays",
		"sumWithOverflow",
		"svg",
		"synonyms",
		"tan",
		"tanh",
		"tcpPort",
		"tgamma",
		"theilsU",
		"throwIf",
		"tid",
		"timeSlot",
		"timeSlots",
		"timeZone",
		"timeZoneOf",
		"timeZoneOffset",
		"timezone",
		"timezoneOf",
		"timezoneOffset",
		"toBool",
		"toColumnTypeName",
		"toDate",
		"toDate32",
		"toDate32OrDefault",
		"toDate32OrNull",
		"toDate32OrZero",
		"toDateOrDefault",
		"toDateOrNull",
		"toDateOrZero",
		"toDateTime",
		"toDateTime32",
		"toDateTime64",
		"toDateTime64OrDefault",
		"toDateTime64OrNull",
		"toDateTime64OrZero",
		"toDateTimeOrDefault",
		"toDateTimeOrNull",
		"toDateTimeOrZero",
		"toDayOfMonth",
		"toDayOfWeek",
		"toDayOfYear",
		"toDecimal128",
		"toDecimal128OrDefault",
		"toDecimal128OrNull",
		"toDecimal128OrZero",
		"toDecimal256",
		"toDecimal256OrDefault",
		"toDecimal256OrNull",
		"toDecimal256OrZero",
		"toDecimal32",
		"toDecimal32OrDefault",
		"toDecimal32OrNull",
		"toDecimal32OrZero",
		"toDecimal64",
		"toDecimal64OrDefault",
		"toDecimal64OrNull",
		"toDecimal64OrZero",
		"toFixedString",
		"toFloat32",
		"toFloat32OrDefault",
		"toFloat32OrNull",
		"toFloat32OrZero",
		"toFloat64",
		"toFloat64OrDefault",
		"toFloat64OrNull",
		"toFloat64OrZero",
		"toHour",
		"toIPv4",
		"toIPv4OrDefault",
		"toIPv4OrNull",
		"toIPv6",
		"toIPv6OrDefault",
		"toIPv6OrNull",
		"toISOWeek",
		"toISOYear",
		"toInt128",
		"toInt128OrDefault",
		"toInt128OrNull",
		"toInt128OrZero",
		"toInt16",
		"toInt16OrDefault",
		"toInt16OrNull",
		"toInt16OrZero",
		"toInt256",
		"toInt256OrDefault",
		"toInt256OrNull",
		"toInt256OrZero",
		"toInt32",
		"toInt32OrDefault",
		"toInt32OrNull",
		"toInt32OrZero",
		"toInt64",
		"toInt64OrDefault",
		"toInt64OrNull",
		"toInt64OrZero",
		"toInt8",
		"toInt8OrDefault",
		"toInt8OrNull",
		"toInt8OrZero",
		"toIntervalDay",
		"toIntervalHour",
		"toIntervalMicrosecond",
		"toIntervalMillisecond",
		"toIntervalMinute",
		"toIntervalMonth",
		"toIntervalNanosecond",
		"toIntervalQuarter",
		"toIntervalSecond",
		"toIntervalWeek",
		"toIntervalYear",
		"toJSONString",
		"toLastDayOfMonth",
		"toLowCardinality",
		"toMinute",
		"toModifiedJulianDay",
		"toModifiedJulianDayOrNull",
		"toMonday",
		"toMonth",
		"toNullable",
		"toQuarter",
		"toRelativeDayNum",
		"toRelativeHourNum",
		"toRelativeMinuteNum",
		"toRelativeMonthNum",
		"toRelativeQuarterNum",
		"toRelativeSecondNum",
		"toRelativeWeekNum",
		"toRelativeYearNum",
		"toSecond",
		"toStartOfDay",
		"toStartOfFifteenMinutes",
		"toStartOfFiveMinute",
		"toStartOfFiveMinutes",
		"toStartOfHour",
		"toStartOfISOYear",
		"toStartOfInterval",
		"toStartOfMicrosecond",
		"toStartOfMillisecond",
		"toStartOfMinute",
		"toStartOfMonth",
		"toStartOfNanosecond",
		"toStartOfQuarter",
		"toStartOfSecond",
		"toStartOfTenMinutes",
		"toStartOfWeek",
		"toStartOfYear",
		"toString",
		"toStringCutToZero",
		"toTime",
		"toTimeZone",
		"toTimezone",
		"toTypeName",
		"toUInt128",
		"toUInt128OrNull",
		"toUInt128OrZero",
		"toUInt16",
		"toUInt16OrDefault",
		"toUInt16OrNull",
		"toUInt16OrZero",
		"toUInt256",
		"toUInt256OrDefault",
		"toUInt256OrNull",
		"toUInt256OrZero",
		"toUInt32",
		"toUInt32OrDefault",
		"toUInt32OrNull",
		"toUInt32OrZero",
		"toUInt64",
		"toUInt64OrDefault",
		"toUInt64OrNull",
		"toUInt64OrZero",
		"toUInt8",
		"toUInt8OrDefault",
		"toUInt8OrNull",
		"toUInt8OrZero",
		"toUUID",
		"toUUIDOrDefault",
		"toUUIDOrNull",
		"toUUIDOrZero",
		"toUnixTimestamp",
		"toUnixTimestamp64Micro",
		"toUnixTimestamp64Milli",
		"toUnixTimestamp64Nano",
		"toValidUTF8",
		"toWeek",
		"toYYYYMM",
		"toYYYYMMDD",
		"toYYYYMMDDhhmmss",
		"toYear",
		"toYearWeek",
		"today",
		"tokens",
		"topK",
		"topKWeighted",
		"topLevelDomain",
		"transactionID",
		"transactionLatestSnapshot",
		"transactionOldestSnapshot",
		"transform",
		"translate",
		"translateUTF8",
		"trimBoth",
		"trimLeft",
		"trimRight",
		"trunc",
		"truncate",
		"tryBase64Decode",
		"tumble",
		"tumbleEnd",
		"tumbleStart",
		"tuple",
		"tupleDivide",
		"tupleDivideByNumber",
		"tupleElement",
		"tupleHammingDistance",
		"tupleMinus",
		"tupleMultiply",
		"tupleMultiplyByNumber",
		"tupleNegate",
		"tuplePlus",
		"tupleToNameValuePairs",
		"ucase",
		"unbin",
		"unhex",
		"uniq",
		"uniqCombined",
		"uniqCombined64",
		"uniqExact",
		"uniqHLL12",
		"uniqTheta",
		"uniqUpTo",
		"upper",
		"upperUTF8",
		"uptime",
		"user",
		"validateNestedArraySizes",
		"varPop",
		"varPopStable",
		"varSamp",
		"varSampStable",
		"vectorDifference",
		"vectorSum",
		"version",
		"visibleWidth",
		"visitParamExtractBool",
		"visitParamExtractFloat",
		"visitParamExtractInt",
		"visitParamExtractRaw",
		"visitParamExtractString",
		"visitParamExtractUInt",
		"visitParamHas",
		"week",
		"welchTTest",
		"windowFunnel",
		"windowID",
		"wkt",
		"wordShingleMinHash",
		"wordShingleMinHashArg",
		"wordShingleMinHashArgCaseInsensitive",
		"wordShingleMinHashArgCaseInsensitiveUTF8",
		"wordShingleMinHashArgUTF8",
		"wordShingleMinHashCaseInsensitive",
		"wordShingleMinHashCaseInsensitiveUTF8",
		"wordShingleMinHashUTF8",
		"wordShingleSimHash",
		"wordShingleSimHashCaseInsensitive",
		"wordShingleSimHashCaseInsensitiveUTF8",
		"wordShingleSimHashUTF8",
		"wyHash64",
		"xor",
		"xxHash32",
		"xxHash64",
		"yandexConsistentHash",
		"yearweek",
		"yesterday",
		"zookeeperSessionUptime",
	}
}

func colNames() []string {
	return []string{
		"AdvEngineID",
		"Age",
		"BrowserCountry",
		"BrowserLanguage",
		"CLID",
		"ClientEventTime",
		"ClientIP",
		"ClientIP6",
		"ClientTimeZone",
		"CodeVersion",
		"ConnectTiming",
		"CookieEnable",
		"CounterClass",
		"CounterID",
		"DNSTiming",
		"DOMCompleteTiming",
		"DOMContentLoadedTiming",
		"DOMInteractiveTiming",
		"DontCountHits",
		"EventDate",
		"EventTime",
		"FUniqID",
		"FetchTiming",
		"FirstPaintTiming",
		"FlashMajor",
		"FlashMinor",
		"FlashMinor2",
		"FromTag",
		"GeneralInterests",
		"GoalsReached",
		"GoodEvent",
		"HID",
		"HTTPError",
		"HasGCLID",
		"HistoryLength",
		"HitColor",
		"IPNetworkID",
		"Income",
		"Interests",
		"IsArtifical",
		"IsDownload",
		"IsEvent",
		"IsLink",
		"IsMobile",
		"IsNotBounce",
		"IsOldCounter",
		"IsParameter",
		"IsRobot",
		"IslandID",
		"JavaEnable",
		"JavascriptEnable",
		"LoadEventEndTiming",
		"LoadEventStartTiming",
		"MobilePhone",
		"MobilePhoneModel",
		"NSToDOMContentLoadedTiming",
		"NetMajor",
		"NetMinor",
		"OS",
		"OpenerName",
		"OpenstatAdID",
		"OpenstatCampaignID",
		"OpenstatServiceName",
		"OpenstatSourceID",
		"PageCharset",
		"ParamCurrency",
		"ParamCurrencyID",
		"ParamOrderID",
		"ParamPrice",
		"Params",
		"ParsedParams.Key1",
		"ParsedParams.Key2",
		"ParsedParams.Key3",
		"ParsedParams.Key4",
		"ParsedParams.Key5",
		"ParsedParams.ValueDouble",
		"RedirectCount",
		"RedirectTiming",
		"Referer",
		"RefererCategories",
		"RefererDomain",
		"RefererHash",
		"RefererRegions",
		"Refresh",
		"RegionID",
		"RemoteIP",
		"RemoteIP6",
		"RequestNum",
		"RequestTry",
		"ResolutionDepth",
		"ResolutionHeight",
		"ResolutionWidth",
		"ResponseEndTiming",
		"ResponseStartTiming",
		"Robotness",
		"SearchEngineID",
		"SearchPhrase",
		"SendTiming",
		"Sex",
		"ShareService",
		"ShareTitle",
		"ShareURL",
		"SilverlightVersion1",
		"SilverlightVersion2",
		"SilverlightVersion3",
		"SilverlightVersion4",
		"SocialAction",
		"SocialNetwork",
		"SocialSourceNetworkID",
		"SocialSourcePage",
		"Title",
		"TraficSourceID",
		"URL",
		"URLCategories",
		"URLDomain",
		"URLHash",
		"URLRegions",
		"UTCEventTime",
		"UTMCampaign",
		"UTMContent",
		"UTMMedium",
		"UTMSource",
		"UTMTerm",
		"UserAgent",
		"UserAgentMajor",
		"UserAgentMinor",
		"UserID",
		"WatchID",
		"WindowClientHeight",
		"WindowClientWidth",
		"WindowName",
		"WithHash",
		"YCLID",
	}
}
