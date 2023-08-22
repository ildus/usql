package ingres

import (
	"fmt"
	md "github.com/xo/usql/drivers/metadata"
	"io"
	"strings"

	"github.com/xo/tblfmt"
	"github.com/xo/usql/dburl"
	"github.com/xo/usql/env"
	"github.com/xo/usql/text"
)

// IngresWriter using an existing db introspector
type IngresWriter struct {
	r             md.Reader
	db            md.DB
	w             io.Writer
	tableTypes    map[rune][]string
	funcTypes     map[rune][]string
	systemSchemas map[string]struct{}

	// custom functions for easier overloading
	listAllDbs func(string, bool) error
}

func NewIngresWriter(r md.Reader, opts ...WriterOption) func(db md.DB, w io.Writer) md.Writer {
	defaultWriter := &IngresWriter{
		r: r,
		tableTypes: map[rune][]string{
			't': {"TABLE", "BASE TABLE", "SYSTEM TABLE", "SYNONYM", "LOCAL TEMPORARY", "GLOBAL TEMPORARY"},
			'v': {"VIEW", "SYSTEM VIEW"},
			's': {"SEQUENCE"},
		},
		funcTypes: map[rune][]string{
			'a': {"AGGREGATE"},
			'n': {"FUNCTION"},
			'p': {"PROCEDURE"},
			't': {"TRIGGER"},
			'w': {"WINDOW"},
		},
		systemSchemas: map[string]struct{}{
			"information_schema": {},
		},
	}
	for _, o := range opts {
		o(defaultWriter)
	}
	return func(db md.DB, w io.Writer) md.Writer {
		defaultWriter.db = db
		defaultWriter.w = w
		return defaultWriter
	}
}

// WriterOption to configure the IngresWriter
type WriterOption func(*IngresWriter)

// WithSystemSchemas that are ignored unless showSystem is true
func WithSystemSchemas(schemas []string) WriterOption {
	return func(w *IngresWriter) {
		w.systemSchemas = make(map[string]struct{}, len(schemas))
		for _, s := range schemas {
			w.systemSchemas[s] = struct{}{}
		}
	}
}

// WithListAllDbs that lists all catalogs
func WithListAllDbs(f func(string, bool) error) WriterOption {
	return func(w *IngresWriter) {
		w.listAllDbs = f
	}
}

// DescribeFunctions matching pattern
func (w IngresWriter) DescribeFunctions(u *dburl.URL, funcTypes, pattern string, verbose, showSystem bool) error {
	r, ok := w.r.(md.FunctionReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\df`, u.Driver)
	}
	types := []string{}
	for k, v := range w.funcTypes {
		if strings.ContainsRune(funcTypes, k) {
			types = append(types, v...)
		}
	}
	sp, tp, err := parsePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse search pattern: %w", err)
	}
	res, err := r.Functions(md.Filter{Schema: sp, Name: tp, Types: types, WithSystem: showSystem})
	if err != nil {
		return fmt.Errorf("failed to list functions: %w", err)
	}
	defer res.Close()

	if !showSystem {
		// in case the reader doesn't implement WithSystem
		res.SetFilter(func(r md.Result) bool {
			_, ok := w.systemSchemas[r.(*md.Function).Schema]
			return !ok
		})
	}

	if _, ok := w.r.(md.FunctionColumnReader); ok {
		for res.Next() {
			f := res.Get()
			f.ArgTypes, err = w.getFunctionColumns(f.Catalog, f.Schema, f.SpecificName)
			if err != nil {
				return fmt.Errorf("failed to get columns of function %s.%s: %w", f.Schema, f.SpecificName, err)
			}
		}
		res.Reset()
	}

	columns := []string{"Schema", "Name", "Result data type", "Argument data types", "Type"}
	if verbose {
		columns = append(columns, "Volatility", "Security", "Language", "Source code")
	}
	res.SetColumns(columns)
	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.Function)
		v := []interface{}{f.Schema, f.Name, f.ResultType, f.ArgTypes, f.Type}
		if verbose {
			v = append(v, f.Volatility, f.Security, f.Language, f.Source)
		}
		return v
	})
	params := env.Pall()
	params["title"] = "List of functions"
	return tblfmt.EncodeAll(w.w, res, params)
}

func (w IngresWriter) getFunctionColumns(c, s, f string) (string, error) {
	r := w.r.(md.FunctionColumnReader)
	cols, err := r.FunctionColumns(md.Filter{Catalog: c, Schema: s, Parent: f})
	if err != nil {
		return "", err
	}
	args := []string{}
	for cols.Next() {
		c := cols.Get()
		// skip result params
		if c.OrdinalPosition == 0 {
			continue
		}
		typ := ""
		if c.Type != "IN" && c.Type != "" {
			typ = c.Type + " "
		}
		name := c.Name
		if name != "" {
			name += " "
		}
		args = append(args, fmt.Sprintf("%s%s%s", typ, name, c.DataType))
	}
	return strings.Join(args, ", "), nil
}

// DescribeTableDetails matching pattern
func (w IngresWriter) DescribeTableDetails(u *dburl.URL, pattern string, verbose, showSystem bool) error {
	sp, tp, err := parsePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse search pattern: %w", err)
	}

	found := 0

	tr, isTR := w.r.(md.TableReader)
	_, isCR := w.r.(md.ColumnReader)
	if isTR && isCR {
		res, err := tr.Tables(md.Filter{Schema: sp, Name: tp, WithSystem: showSystem})
		if err != nil {
			return fmt.Errorf("failed to list tables: %w", err)
		}
		defer res.Close()
		if !showSystem {
			// in case the reader doesn't implement WithSystem
			res.SetFilter(func(r md.Result) bool {
				_, ok := w.systemSchemas[r.(*md.Table).Schema]
				return !ok
			})
		}
		for res.Next() {
			t := res.Get()
			err = w.describeTableDetails(t.Type, t.Schema, t.Name, verbose, showSystem)
			if err != nil {
				return fmt.Errorf("failed to describe %s %s.%s: %w", t.Type, t.Schema, t.Name, err)
			}
			found++
		}
	}

	if _, ok := w.r.(md.SequenceReader); ok {
		foundSeq, err := w.describeSequences(sp, tp, verbose, showSystem)
		if err != nil {
			return fmt.Errorf("failed to describe sequences: %w", err)
		}
		found += foundSeq
	}

	ir, isIR := w.r.(md.IndexReader)
	_, isICR := w.r.(md.IndexColumnReader)
	if isIR && isICR {
		res, err := ir.Indexes(md.Filter{Schema: sp, Name: tp, WithSystem: showSystem})
		if err != nil && err != text.ErrNotSupported {
			return fmt.Errorf("failed to list indexes for table %s: %w", tp, err)
		}
		if res != nil {
			defer res.Close()
			if !showSystem {
				// in case the reader doesn't implement WithSystem
				res.SetFilter(func(r md.Result) bool {
					_, ok := w.systemSchemas[r.(*md.Index).Schema]
					return !ok
				})
			}
			for res.Next() {
				i := res.Get()
				err = w.describeIndex(i)
				if err != nil {
					return fmt.Errorf("failed to describe index %s from table %s.%s: %w", i.Name, i.Schema, i.Table, err)
				}
				found++
			}
		}
	}

	if found == 0 {
		fmt.Fprintf(w.w, text.RelationNotFound, pattern)
		fmt.Fprintln(w.w)
	}
	return nil
}

func (w IngresWriter) describeTableDetails(typ, sp, tp string, verbose, showSystem bool) error {
	r := w.r.(md.ColumnReader)
	res, err := r.Columns(md.Filter{Schema: sp, Parent: tp, WithSystem: showSystem})
	if err != nil {
		return fmt.Errorf("failed to list columns for table %s: %w", tp, err)
	}
	defer res.Close()

	columns := []string{"Name", "Type", "Nullable", "Default"}
	if verbose {
		columns = append(columns, "Size", "Decimal Digits", "Radix", "Octet Length")
	}
	res.SetColumns(columns)
	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.Column)
		v := []interface{}{f.Name, f.DataType, f.IsNullable, f.Default}
		if verbose {
			v = append(v, f.ColumnSize, f.DecimalDigits, f.NumPrecRadix, f.CharOctetLength)
		}
		return v
	})
	params := env.Pall()
	params["title"] = fmt.Sprintf("%s %s\n", typ, qualifiedIdentifier(sp, tp))
	return w.encodeWithSummary(res, params, w.tableDetailsSummary(sp, tp))
}

func (w IngresWriter) encodeWithSummary(res tblfmt.ResultSet, params map[string]string, summary func(io.Writer, int) (int, error)) error {
	newEnc, opts := tblfmt.FromMap(params)
	opts = append(opts, tblfmt.WithSummary(
		map[int]func(io.Writer, int) (int, error){
			-1: summary,
		},
	))
	enc, err := newEnc(res, opts...)
	if err != nil {
		return err
	}
	return enc.EncodeAll(w.w)
}

func (w IngresWriter) tableDetailsSummary(sp, tp string) func(io.Writer, int) (int, error) {
	return func(out io.Writer, _ int) (int, error) {
		err := w.describeTableIndexes(out, sp, tp)
		if err != nil {
			return 0, err
		}
		err = w.describeTableConstraints(
			out,
			md.Filter{Schema: sp, Parent: tp},
			func(r md.Result) bool {
				c := r.(*md.Constraint)
				return c.Type == "CHECK" && c.CheckClause != "" && !strings.HasSuffix(c.CheckClause, " IS NOT NULL")
			},
			"Check constraints:",
			func(out io.Writer, c *md.Constraint) error {
				_, err := fmt.Fprintf(out, "  \"%s\" %s (%s)\n", c.Name, c.Type, c.CheckClause)
				return err
			},
		)
		if err != nil {
			return 0, err
		}
		err = w.describeTableConstraints(
			out,
			md.Filter{Schema: sp, Parent: tp},
			func(r md.Result) bool { return r.(*md.Constraint).Type == "FOREIGN KEY" },
			"Foreign-key constraints:",
			func(out io.Writer, c *md.Constraint) error {
				columns, foreignColumns, err := w.getConstraintColumns(c.Catalog, c.Schema, c.Table, c.Name)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(out, "  \"%s\" %s (%s) REFERENCES %s(%s) ON UPDATE %s ON DELETE %s\n",
					c.Name,
					c.Type,
					columns,
					c.ForeignTable,
					foreignColumns,
					c.UpdateRule,
					c.DeleteRule)
				return err
			},
		)
		if err != nil {
			return 0, err
		}
		err = w.describeTableConstraints(
			out,
			md.Filter{Schema: sp, Reference: tp},
			func(r md.Result) bool { return r.(*md.Constraint).Type == "FOREIGN KEY" },
			"Referenced by:",
			func(out io.Writer, c *md.Constraint) error {
				columns, foreignColumns, err := w.getConstraintColumns(c.Catalog, c.Schema, c.Table, c.Name)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(out, "  TABLE \"%s\" CONSTRAINT \"%s\" %s (%s) REFERENCES %s(%s) ON UPDATE %s ON DELETE %s\n",
					c.Table,
					c.Name,
					c.Type,
					columns,
					c.ForeignTable,
					foreignColumns,
					c.UpdateRule,
					c.DeleteRule)
				return err
			},
		)
		err = w.describeTableTriggers(out, sp, tp)
		if err != nil {
			return 0, err
		}
		return 0, err
	}
}

func (w IngresWriter) describeTableTriggers(out io.Writer, sp, tp string) error {
	r, ok := w.r.(md.TriggerReader)
	if !ok {
		return nil
	}
	res, err := r.Triggers(md.Filter{Schema: sp, Parent: tp})
	if err != nil && err != text.ErrNotSupported {
		return fmt.Errorf("failed to list triggers for table %s: %w", tp, err)
	}
	if res == nil {
		return nil
	}
	defer res.Close()

	if res.Len() == 0 {
		return nil
	}
	fmt.Fprintln(out, "Triggers:")
	for res.Next() {
		t := res.Get()
		fmt.Fprintf(out, "  \"%s\" %s\n", t.Name, t.Definition)
	}
	return nil
}

func (w IngresWriter) describeTableIndexes(out io.Writer, sp, tp string) error {
	r, ok := w.r.(md.IndexReader)
	if !ok {
		return nil
	}
	res, err := r.Indexes(md.Filter{Schema: sp, Parent: tp})
	if err != nil && err != text.ErrNotSupported {
		return fmt.Errorf("failed to list indexes for table %s: %w", tp, err)
	}
	if res == nil {
		return nil
	}
	defer res.Close()

	if res.Len() == 0 {
		return nil
	}
	fmt.Fprintln(out, "Indexes:")
	for res.Next() {
		i := res.Get()
		primary := ""
		unique := ""
		if i.IsPrimary == md.YES {
			primary = "PRIMARY_KEY, "
		}
		if i.IsUnique == md.YES {
			unique = "UNIQUE, "
		}
		i.Columns, err = w.getIndexColumns(i.Catalog, i.Schema, i.Table, i.Name)
		if err != nil {
			return fmt.Errorf("failed to get columns of index %s: %w", i.Name, err)
		}
		fmt.Fprintf(out, "  \"%s\" %s%s%s (%s)\n", i.Name, primary, unique, i.Type, i.Columns)
	}
	return nil
}

func (w IngresWriter) getIndexColumns(c, s, t, i string) (string, error) {
	r := w.r.(md.IndexColumnReader)
	cols, err := r.IndexColumns(md.Filter{Catalog: c, Schema: s, Parent: t, Name: i})
	if err != nil {
		return "", err
	}
	result := []string{}
	for cols.Next() {
		result = append(result, cols.Get().Name)
	}
	return strings.Join(result, ", "), nil
}

func (w IngresWriter) describeTableConstraints(out io.Writer, filter md.Filter, postFilter func(r md.Result) bool, label string, printer func(io.Writer, *md.Constraint) error) error {
	r, ok := w.r.(md.ConstraintReader)
	if !ok {
		return nil
	}
	res, err := r.Constraints(filter)
	if err != nil && err != text.ErrNotSupported {
		return fmt.Errorf("failed to list constraints: %w", err)
	}
	if res == nil {
		return nil
	}
	defer res.Close()

	res.SetFilter(postFilter)
	if res.Len() == 0 {
		return nil
	}
	fmt.Fprintln(out, label)
	for res.Next() {
		c := res.Get()
		err := printer(out, c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w IngresWriter) getConstraintColumns(c, s, t, n string) (string, string, error) {
	r := w.r.(md.ConstraintColumnReader)
	cols, err := r.ConstraintColumns(md.Filter{Catalog: c, Schema: s, Parent: t, Name: n})
	if err != nil {
		return "", "", err
	}
	columns := []string{}
	foreignColumns := []string{}
	for cols.Next() {
		columns = append(columns, cols.Get().Name)
		foreignColumns = append(foreignColumns, cols.Get().ForeignName)
	}
	return strings.Join(columns, ", "), strings.Join(foreignColumns, ", "), nil
}

func (w IngresWriter) describeSequences(sp, tp string, verbose, showSystem bool) (int, error) {
	r := w.r.(md.SequenceReader)
	res, err := r.Sequences(md.Filter{Schema: sp, Name: tp, WithSystem: showSystem})
	if err != nil && err != text.ErrNotSupported {
		return 0, err
	}
	if res == nil {
		return 0, nil
	}
	defer res.Close()

	found := 0
	for res.Next() {
		s := res.Get()
		// wrap current record into a separate recordSet
		rows := md.NewSequenceSet([]md.Sequence{*s})
		params := env.Pall()
		params["footer"] = "off"
		params["title"] = fmt.Sprintf("Sequence \"%s.%s\"\n", s.Schema, s.Name)
		err = tblfmt.EncodeAll(w.w, rows, params)
		if err != nil {
			return 0, err
		}
		// TODO footer should say which table this sequence belongs to
		found++
	}

	return found, nil
}

func (w IngresWriter) describeIndex(i *md.Index) error {
	r := w.r.(md.IndexColumnReader)
	res, err := r.IndexColumns(md.Filter{Schema: i.Schema, Parent: i.Table, Name: i.Name})
	if err != nil {
		return fmt.Errorf("failed to get index columns: %w", err)
	}
	defer res.Close()
	if res.Len() == 0 {
		return nil
	}

	res.SetColumns([]string{"Name", "Type"})
	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.IndexColumn)
		return []interface{}{f.Name, f.DataType}
	})

	params := env.Pall()
	params["title"] = fmt.Sprintf("Index %s\n", qualifiedIdentifier(i.Schema, i.Name))
	return w.encodeWithSummary(res, params, func(out io.Writer, _ int) (int, error) {
		primary := ""
		if i.IsPrimary == md.YES {
			primary = "primary key, "
		}
		_, err := fmt.Fprintf(out, "%s%s, for table %s", primary, i.Type, i.Table)
		return 0, err
	})
}

// ListAllDbs matching pattern
func (w IngresWriter) ListAllDbs(u *dburl.URL, pattern string, verbose bool) error {
	if w.listAllDbs != nil {
		return w.listAllDbs(pattern, verbose)
	}
	r, ok := w.r.(md.CatalogReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\l`, u.Driver)
	}
	res, err := r.Catalogs(md.Filter{Name: pattern})
	if err != nil {
		return fmt.Errorf("failed to list catalogs: %w", err)
	}
	defer res.Close()

	params := env.Pall()
	params["title"] = "List of databases"
	return tblfmt.EncodeAll(w.w, res, params)
}

// ListTables matching pattern
func (w IngresWriter) ListTables(u *dburl.URL, tableTypes, pattern string, verbose, showSystem bool) error {
	r, ok := w.r.(md.TableReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\dt`, u.Driver)
	}
	types := []string{}
	for k, v := range w.tableTypes {
		if strings.ContainsRune(tableTypes, k) {
			types = append(types, v...)
		}
	}
	sp, tp, err := parsePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse search pattern: %w", err)
	}
	res, err := r.Tables(md.Filter{Schema: sp, Name: tp, Types: types, WithSystem: showSystem})
	if err != nil {
		return fmt.Errorf("failed to list tables: %w", err)
	}
	defer res.Close()
	if !showSystem {
		// in case the reader doesn't implement WithSystem
		res.SetFilter(func(r md.Result) bool {
			_, ok := w.systemSchemas[r.(*md.Table).Schema]
			return !ok
		})
	}
	if res.Len() == 0 {
		fmt.Fprintf(w.w, text.RelationNotFound, pattern)
		fmt.Fprintln(w.w)
		return nil
	}
	columns := []string{"Name", "Type"}
	if verbose {
		columns = append(columns, "Rows", "Size", "Comment")
	}
	res.SetColumns(columns)
	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.Table)
		v := []interface{}{f.Name, f.Type}
		if verbose {
			v = append(v, f.Rows, f.Size, f.Comment)
		}
		return v
	})

	params := env.Pall()
	params["title"] = "List of relations"
	return tblfmt.EncodeAll(w.w, res, params)
}

// ListSchemas matching pattern
func (w IngresWriter) ListSchemas(u *dburl.URL, pattern string, verbose, showSystem bool) error {
	r, ok := w.r.(md.SchemaReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\d`, u.Driver)
	}
	res, err := r.Schemas(md.Filter{Name: pattern, WithSystem: showSystem})
	if err != nil {
		return fmt.Errorf("failed to list schemas: %w", err)
	}
	defer res.Close()

	if !showSystem {
		// in case the reader doesn't implement WithSystem
		res.SetFilter(func(r md.Result) bool {
			_, ok := w.systemSchemas[r.(*md.Schema).Schema]
			return !ok
		})
	}
	params := env.Pall()
	params["title"] = "List of schemas"
	return tblfmt.EncodeAll(w.w, res, params)
}

// ListIndexes matching pattern
func (w IngresWriter) ListIndexes(u *dburl.URL, pattern string, verbose, showSystem bool) error {
	r, ok := w.r.(md.IndexReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\di`, u.Driver)
	}
	sp, tp, err := parsePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse search pattern: %w", err)
	}
	res, err := r.Indexes(md.Filter{Schema: sp, Name: tp, WithSystem: showSystem})
	if err != nil {
		return fmt.Errorf("failed to list indexes: %w", err)
	}
	defer res.Close()

	if !showSystem {
		// in case the reader doesn't implement WithSystem
		res.SetFilter(func(r md.Result) bool {
			_, ok := w.systemSchemas[r.(*md.Index).Schema]
			return !ok
		})
	}
	if res.Len() == 0 {
		fmt.Fprintf(w.w, text.RelationNotFound, pattern)
		fmt.Fprintln(w.w)
		return nil
	}

	columns := []string{"Schema", "Name", "Type", "Table"}
	if verbose {
		columns = append(columns, "Primary?", "Unique?")
	}
	res.SetColumns(columns)
	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.Index)
		v := []interface{}{f.Schema, f.Name, f.Type, f.Table}
		if verbose {
			v = append(v, f.IsPrimary, f.IsUnique)
		}
		return v
	})

	params := env.Pall()
	params["title"] = "List of indexes"
	return tblfmt.EncodeAll(w.w, res, params)
}

// ShowStats of columns for tables matching pattern
func (w IngresWriter) ShowStats(u *dburl.URL, statTypes, pattern string, verbose bool, k int) error {
	r, ok := w.r.(md.ColumnStatReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\ss`, u.Driver)
	}
	sp, tp, err := parsePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse search pattern: %w", err)
	}

	rows := int64(0)
	tr, ok := w.r.(md.TableReader)
	if ok {
		tables, err := tr.Tables(md.Filter{Schema: sp, Name: tp})
		if err != nil {
			return fmt.Errorf("failed to get table entry: %w", err)
		}
		defer tables.Close()
		if tables.Next() {
			rows = tables.Get().Rows
		}
	}

	types := []string{"basic"}
	if verbose {
		types = append(types, "extended")
	}
	res, err := r.ColumnStats(md.Filter{Schema: sp, Parent: tp, Types: types})
	if err != nil {
		return fmt.Errorf("failed to get column stats: %w", err)
	}
	defer res.Close()

	if res.Len() == 0 {
		fmt.Fprintf(w.w, text.RelationNotFound, pattern)
		fmt.Fprintln(w.w)
		return nil
	}
	columns := []string{"Schema", "Table", "Name", "Average width", "Nulls fraction", "Distinct values", "Dist. fraction"}
	if verbose {
		columns = append(columns, "Minimum value", "Maximum value", "Mean value", "Top N common values", "Top N values freqs")
	}
	res.SetColumns(columns)
	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.ColumnStat)
		freqs := []string{}
		for _, freq := range f.TopNFreqs {
			freqs = append(freqs, fmt.Sprintf("%.4f", freq))
		}
		n := k
		if n > len(freqs) {
			n = len(freqs)
		}
		distFrac := 1.0
		if rows != 0 && f.NumDistinct != rows {
			distFrac = float64(f.NumDistinct) / float64(rows)
		}
		v := []interface{}{
			f.Schema,
			f.Table,
			f.Name,
			f.AvgWidth,
			f.NullFrac,
			f.NumDistinct,
			fmt.Sprintf("%.4f", distFrac),
		}
		if verbose {
			v = append(v,
				f.Min,
				f.Max,
				f.Mean,
				strings.Join(f.TopN[:n], ", "),
				strings.Join(freqs[:n], ", "),
			)
		}
		return v
	})

	params := env.Pall()
	params["title"] = "Column stats"
	return tblfmt.EncodeAll(w.w, res, params)
}

// ListPrivilegeSummaries matching pattern
func (w IngresWriter) ListPrivilegeSummaries(u *dburl.URL, pattern string, showSystem bool) error {
	r, ok := w.r.(md.PrivilegeSummaryReader)
	if !ok {
		return fmt.Errorf(text.NotSupportedByDriver, `\dp`, u.Driver)
	}
	sp, tp, err := parsePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse search pattern: %w", err)
	}
	// filter for tables, views and sequences
	const tableTypes = "tvms"
	types := []string{}
	for k, v := range w.tableTypes {
		if strings.ContainsRune(tableTypes, k) {
			types = append(types, v...)
		}
	}
	res, err := r.PrivilegeSummaries(md.Filter{Schema: sp, Name: tp, WithSystem: showSystem, Types: types})
	if err != nil {
		return fmt.Errorf("failed to list table privileges: %w", err)
	}
	defer res.Close()
	if !showSystem {
		// in case the reader doesn't implement WithSystem
		res.SetFilter(func(r md.Result) bool {
			_, ok := w.systemSchemas[r.(*md.PrivilegeSummary).Schema]
			return !ok
		})
	}

	res.SetScanValues(func(r md.Result) []interface{} {
		f := r.(*md.PrivilegeSummary)

		v := []interface{}{
			f.Schema,
			f.Name,
			f.ObjectType,
			f.ObjectPrivileges,
			f.ColumnPrivileges,
		}
		return v
	})

	params := env.Pall()
	params["title"] = "Access privileges"
	return tblfmt.EncodeAll(w.w, res, params)
}

func parsePattern(pattern string) (string, string, error) {
	// TODO do proper escaping, quoting etc
	if strings.ContainsRune(pattern, '.') {
		parts := strings.SplitN(pattern, ".", 2)
		return strings.ReplaceAll(parts[0], "*", "%"), strings.ReplaceAll(parts[1], "*", "%"), nil
	}
	return "", strings.ReplaceAll(pattern, "*", "%"), nil
}

func qualifiedIdentifier(schema, name string) string {
	if schema == "" {
		return fmt.Sprintf("\"%s\"", name)
	}
	return fmt.Sprintf("\"%s.%s\"", schema, name)
}
