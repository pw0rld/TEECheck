// Planned Joern query stub.
//
// Goal:
// 1. Find TA entrypoints such as TA_InvokeCommandEntryPoint.
// 2. Find expressions that read params[i].memref.buffer or params[i].memref.size.
// 3. Emit candidate IDs and source locations.
//
// Expected next iteration:
// - use Joern traversals over calls, identifiers, field accesses, and CFG nodes
// - write JSON evidence packages to an output directory
