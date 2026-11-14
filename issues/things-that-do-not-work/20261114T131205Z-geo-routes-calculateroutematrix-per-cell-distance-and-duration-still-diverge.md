Issue-Source: trace-sweep-divergence
Issue-Trace: geo-routes-calculate-route-matrix-basic-success
Issue-Step: task#1
Issue-Severity: HIGH
Issue-Corpus: simparity-wire-aws-v1
Issue-Corpus-Kind: wire
Issue-Trace-Ids: geo-routes-calculate-route-matrix-basic-success
Issue-Shape-Id: com.amazonaws.georoutes#RoutesService
Issue-Key: geo-routes|CalculateRouteMatrix|2xx->2xx|$.RouteMatrix[*][*].Distance
Issue-Key: geo-routes|CalculateRouteMatrix|2xx->2xx|$.RouteMatrix[*][*].Duration
Issue-Commit: f408e2feb866bce0b1ce46e353689f133faa9408

# CalculateRouteMatrix per-cell Distance and Duration still diverge from the recorded road-network metrics

> _Note: this issue was identified against the code base at commit `f408e2feb866bce0b1ce46e353689f133faa9408`. If you are an issue fixer working on this, the code base you are currently working in can have drifted, so you might need to trace the issue back to the current code base._

## Operation
CalculateRouteMatrix

## Description
CalculateRouteMatrix answers HTTP 200 with a structurally correct body -- the matrix dimensions, RoutingBoundary echo, ErrorCount and per-cell Error codes all agree with the recordings -- but the two quantitative members of every successful cell are produced by a distance/duration model that is not the road-network model AWS answers with. This bundle has ONE cause.

NOTE ON PRIOR WORK: issue 20261107T215853Z-geo-routes-calculateroutematrix-cell-distance-and-duration-still-diverge-from.md is RESOLVED (status fixed) and therefore covers none of this failure; two of its three causes (the 5x5 matrix fixture geo-routes-calculate-route-matrix-cap-exceeded-rejected#task#2 and the mixed routable/unroutable fixture geo-routes-calculate-route-matrix-per-entry-error-codes#task#2) now replay clean, but the square-matrix cause still reproduces with NEW values and a NEW sign of error, so the metric model was changed and is still wrong. The earlier resolved issue 20261029T172141Z-geo-routes-calculateroutematrix-matrix-synthesis-diverges-wrong-distance-duration-dropped.md likewise does not cover it. The OPEN issue 20261103T183228Z-geo-routes-route-synthesis-ignores-the-road-network.md covers the equivalent metric defect in CalculateRoutes / OptimizeWaypoints / SnapToRoads only; it carries no CalculateRouteMatrix replay key, so closing it does not close this. The shared road-graph traversal it asks for is nonetheless the natural place to fix this operation too.

Cause 1 of 1: square 2x2 matrix -- every cell's Distance and Duration diverge (fixture geo-routes-calculate-route-matrix-basic-success, step task#1).
AWS: Smithy georoutes#CalculateRouteMatrix -> POST /v2/route-matrix, http code 200; CalculateRouteMatrixResponse.RouteMatrix @required (RouteMatrix, list of rows of RouteMatrixEntry -- "Each row corresponds to one entry in Origins. Each entry in the row corresponds to the route from that entry in Origins to an entry in Destination positions"). RouteMatrixEntry.Distance (DistanceMeters, long, @required, @default 0, @range 0..4294967295, @sensitive) is documented "The total distance of travel for the route"; RouteMatrixEntry.Duration (DurationSeconds, long, @required, @default 0, @range 0..4294967295, @sensitive) is "The expected duration of travel for the route", Unit: seconds. The model does not specify the routing algorithm, so for the metric values themselves: recorded behavior only -- for a fixed Origins x Destinations set AWS returns a deterministic per-cell pair whose distance is the road-network distance and whose duration is consistent with it at a road-network average speed, uniformly across the cells of one matrix.
Emulator: for the same fixed fixture coordinates it returns, in all four cells, BOTH a short distance and a short duration -- distance 2% to 12% below the recorded value and duration 11% to 24% below it, with the two errors uncorrelated from cell to cell. The implied average speed therefore varies per cell and runs well above a road speed on some pairs (one cell comes back at roughly 100 km/h where the recording implies about 80 km/h). These are reproducible values, not per-run noise: the request coordinates are fixed in the fixture, so this is simply a different and internally inconsistent metric model. Note the direction of the duration error has FLIPPED since the resolved issue (durations used to be long, they are now short), confirming the computation was replaced rather than corrected.
Why: a client that sizes a delivery window, picks a nearest depot, or filters origin/destination pairs against a duration budget gets both different ETAs and a different cell ranking than it gets from AWS. Because the per-cell error is not a constant factor, a client cannot compensate for it, and understated durations let pairs pass client-side time limits that AWS's answer would reject, while the short distances under-count distance-based cost.
Fix: the CalculateRouteMatrix handler's per-cell metric computation (the matrix-synthesis component), which should derive Distance and Duration from the same road-graph traversal the other route-metric producers use. Neither the serializer nor the response builder is implicated -- shape, ErrorCount, per-cell Error and RoutingBoundary all match.
Traces: geo-routes-calculate-route-matrix-basic-success#task#1. No status, error code or error message diverges: the step is HTTP 200 on both sides.

## Evidence
Replay of the simparity-wire-aws-v1 wire corpus, cluster service=geo-routes|CalculateRouteMatrix|status=200->200. expected_status 200, actual_status 200 -- the divergence is entirely in response body values. The integers below are the recorded fixture values and are EXAMPLES of the rule (a road-network distance with a mutually consistent duration), not literal requirements; a fix must reproduce AWS's metric model, not these specific numbers.

Cause 1 -- geo-routes-calculate-route-matrix-basic-success#task#1, POST /v2/route-matrix, 2 Origins x 2 Destinations, 200 -> 200:
  $.RouteMatrix[0][0].Distance: expected 22249, got 20490   (-7.9%)
  $.RouteMatrix[0][0].Duration: expected 976,  got 866     (-11.3%)
  $.RouteMatrix[0][1].Distance: expected 54104, got 47735   (-11.8%)
  $.RouteMatrix[0][1].Duration: expected 2047, got 1721    (-15.9%)
  $.RouteMatrix[1][0].Distance: expected 27518, got 26313   (-4.4%)
  $.RouteMatrix[1][0].Duration: expected 1247, got 952     (-23.7%)
  $.RouteMatrix[1][1].Distance: expected 59553, got 58336   (-2.0%)
  $.RouteMatrix[1][1].Duration: expected 2354, got 2051    (-12.9%)

All four cells are short on both members, and the ratio of the two errors differs per cell: cell [1][0] implies about 27.6 m/s (~99 km/h) where the recording implies about 22.1 m/s (~79 km/h), while cell [0][0] implies about 23.7 m/s against a recorded 22.8 m/s. That per-cell inconsistency is the signature of a synthesized metric rather than a graph traversal.

No $.ErrorCount, $.RouteMatrix[*][*].Error, $.RoutingBoundary or x-amz-geo-pricing-bucket divergence is reported on this step, and the 5x5 and mixed routable/unroutable matrix fixtures no longer diverge at all -- only the square-matrix metrics remain wrong.

## Steps to Reproduce
1. Boot the emulator from this checkout and replay the simparity-wire-aws-v1 wire corpus.
2. Replay fixture geo-routes-calculate-route-matrix-basic-success, step task#1 (POST /v2/route-matrix with the recorded 2 Origins x 2 Destinations request).
3. Compare every $.RouteMatrix[i][j].Distance and .Duration against the recorded response. All four cells diverge: distance is short and duration is short, by differing proportions.
4. Check that the implied average speed per cell (Distance / Duration) matches the recording's for that pair; it does not, so the two members are not mutually consistent.
5. The step returns HTTP 200 both from AWS and from the emulator, with matching ErrorCount, per-cell Error and RoutingBoundary -- the divergence is purely in the synthesized per-cell metrics.
6. Re-replay this step to confirm a fix; also re-replay geo-routes-calculate-route-matrix-cap-exceeded-rejected#task#2 (5x5) and geo-routes-calculate-route-matrix-per-entry-error-codes#task#2 (mixed routable/unroutable), which currently PASS, to confirm the new metric model does not regress them.
