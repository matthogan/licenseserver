// Package exportdata defines the stable, public data-export schema emitted by
// licd. It deliberately contains no database row types or server dependencies.
//
// SchemaVersion changes only for an incompatible record or bundle change.
// FormatVersion follows semantic versioning within that schema. Consumers
// should reject unsupported schema versions and ignore additive fields from a
// compatible minor format release.
package exportdata
