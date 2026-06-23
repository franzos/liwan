import cardStyles from "./dimensions/dimensions.module.css";
import styles from "./index.module.css";

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";

import type { DateRange } from "@/api/ranges";
import type { Dimension, DimensionFilter, DimensionTableRow, Metric, ProjectResponse } from "@/constants";
import { dimensions, metricNames, metrics } from "@/constants";
import { useDimension, useProject, useProjectGraph, useProjectStats } from "@/hooks/api";
import { useMetric, useRange } from "@/hooks/persist";
import { cls } from "@/utils";
import { DimensionDropdownCard, DimensionTable, DimensionTabs, DimensionTabsCard, PageDimensionTabsCard } from "./dimensions";
import { SelectEntity } from "./entity";
import { SelectFilters } from "./filter";
import { LineGraph } from "./graph";
import { SelectMetrics } from "./metric";
import { ProjectHeader } from "./project-header";
import { SelectRange } from "./range";

const Worldmap = lazy(() => import("./worldmap").then((module) => ({ default: module.Worldmap })));
export type ProjectQuery = {
	project: ProjectResponse;
	metric: Metric;
	range: DateRange;
	filters: DimensionFilter[];
};

const getDimensionFilter = (dimension: Dimension, value: string): DimensionFilter => {
	if (dimension === "city")
		// remove the first two characters from the dimension value
		// which are the country code
		return {
			dimension: "city",
			filterType: "equal",
			value: value.slice(2),
		};

	if (dimension === "mobile")
		return {
			dimension: "mobile",
			filterType: value === "true" ? "is_true" : "is_false",
		};

	if (value === "Unknown")
		return {
			dimension,
			filterType: "is_null",
		};

	return {
		dimension,
		filterType: "equal",
		value: value,
	};
};

const isEntityFilter = (f: DimensionFilter) => f.dimension === "entity_id" && f.filterType === "equal";

export const Project = () => {
	const [projectId, setProjectId] = useState<string | undefined>();
	const [filters, setFilters] = useState<DimensionFilter[]>([]);

	const { metric, setMetric } = useMetric();
	const { range, setRange } = useRange();

	useEffect(() => {
		if (typeof window === "undefined") return;
		setProjectId(window?.document.location.pathname.split("/").pop());
	}, []);

	const { project, notFound } = useProject(projectId);
	// The event scope rides in the filters as a non-pageview `event = X` equality filter.
	// When `event` is hidden via display settings it's stripped from `visibleFilters` (so reports
	// revert to pageview); ignore the scope here too, otherwise metric-hiding would desync.
	const eventHidden = project?.hiddenDimensions.includes("event") ?? false;
	const eventScope = useMemo(
		() =>
			eventHidden
				? undefined
				: (filters.find((f) => f.dimension === "event" && f.filterType === "equal" && f.value && f.value !== "pageview")
						?.value ?? undefined),
		[filters, eventHidden],
	);
	const sessionMetricsHidden = Boolean(eventScope);
	const visibleMetrics: Metric[] = useMemo(
		() =>
			metrics.filter(
				(item) =>
					!project?.hiddenMetrics.includes(item) &&
					!(sessionMetricsHidden && (item === "bounce_rate" || item === "avg_time_on_site")),
			),
		[project?.hiddenMetrics, sessionMetricsHidden],
	);
	const activeMetric = visibleMetrics.includes(metric) ? metric : visibleMetrics[0];
	const reportMetric: Metric = activeMetric ?? "views";
	const visibleFilters = useMemo(
		() => filters.filter((filter) => !project?.hiddenDimensions.includes(filter.dimension)),
		[filters, project?.hiddenDimensions],
	);
	const {
		graph,
		isUpdating: graphUpdating,
		isLoading: graphLoading,
	} = useProjectGraph({
		projectId,
		metric: reportMetric,
		range,
		filters: visibleFilters,
		enabled: Boolean(activeMetric),
	});
	const { stats } = useProjectStats({
		projectId,
		metric: reportMetric,
		range,
		filters: visibleFilters,
		enabled: Boolean(activeMetric),
	});

	const query = useMemo<ProjectQuery>(
		() => ({
			// biome-ignore lint/style/noNonNullAssertion: this is safe because code using this query will only run when project is defined.
			project: project!,
			metric: reportMetric,
			range,
			filters: visibleFilters,
		}),
		[project, reportMetric, range, visibleFilters],
	);

	useEffect(() => {
		if (activeMetric && activeMetric !== metric) setMetric(activeMetric);
	}, [activeMetric, metric, setMetric]);

	const toggleFilter = useCallback(
		(filter: DimensionFilter) => {
			const index = filters.findIndex((f) => f.dimension === filter.dimension && f.filterType === filter.filterType);
			if (index === -1) {
				setFilters([...filters, filter]);
			} else {
				setFilters(filters.filter((_, i) => i !== index));
			}
		},
		[filters],
	);

	const selectedEntityId = useMemo(() => filters.find(isEntityFilter)?.value ?? undefined, [filters]);

	// The entity scope has its own dropdown, so keep it out of the chip row.
	const chipFilters = useMemo(() => visibleFilters.filter((f) => !isEntityFilter(f)), [visibleFilters]);

	const setSelectedEntity = useCallback((entityId?: string) => {
		setFilters((prev) => {
			const rest = prev.filter((f) => !isEntityFilter(f));
			return entityId ? [...rest, { dimension: "entity_id", filterType: "equal", value: entityId }] : rest;
		});
	}, []);

	// SelectFilters only edits chip filters; merge back everything kept off the chip row (entity scope + hidden dimensions).
	const onChangeChipFilters = useCallback(
		(next: DimensionFilter[]) => {
			setFilters((prev) =>
				next.concat(prev.filter((f) => isEntityFilter(f) || (project?.hiddenDimensions ?? []).includes(f.dimension))),
			);
		},
		[project?.hiddenDimensions],
	);

	const onSelectDimRow = useCallback(
		(value: DimensionTableRow, dimension: Dimension) => {
			// The event scope is single-select: clicking a different event switches scope, clicking the active one clears it.
			if (dimension === "event") {
				// Build the filter directly — `getDimensionFilter` special-cases "Unknown" into an is_null
				// filter, which would break the event scope for an event literally named "Unknown".
				const eventFilter: DimensionFilter = { dimension: "event", filterType: "equal", value: value.dimensionValue };
				setFilters((prev) => {
					const active = prev.find((f) => f.dimension === "event" && f.value === value.dimensionValue);
					const rest = prev.filter((f) => f.dimension !== "event");
					return active ? rest : [...rest, eventFilter];
				});
				return;
			}
			toggleFilter(getDimensionFilter(dimension, value.dimensionValue));
		},
		[toggleFilter],
	);

	if (notFound) {
		return <div className={styles.notFound}>Project not found</div>;
	}

	if (!project) return null;
	const visibleDimensions = (items: Dimension[]) =>
		items.filter((dimension) => !project.hiddenDimensions.includes(dimension));
	const pageDimensions = visibleDimensions(["url", "url_entry", "url_exit", "fqdn"]);
	const campaignDimensions = visibleDimensions([
		"referrer",
		"utm_source",
		"utm_medium",
		"utm_campaign",
		"utm_content",
		"utm_term",
	]);
	const geoDimensions = visibleDimensions(["country", "city"]);
	const technologyDimensions = visibleDimensions(["platform", "browser"]);
	const deviceDimensions = visibleDimensions(["mobile", "screen_width", "orientation"]);

	return (
		<div className={styles.project}>
			<Suspense fallback={null}>
				<div>
					<div className={styles.projectHeader}>
						<ProjectHeader project={project} stats={stats} />
						<div className={styles.headerControls}>
							<SelectRange onSelect={setRange} range={range} projectId={project.id} />
							{project.entities.length > 1 && (
								<SelectEntity entities={project.entities} value={selectedEntityId} onChange={setSelectedEntity} />
							)}
						</div>
					</div>
					<SelectMetrics
						data={stats}
						metric={reportMetric}
						metrics={visibleMetrics}
						setMetric={setMetric}
						className={styles.projectStats}
					/>
					<SelectFilters
						value={chipFilters}
						onChange={onChangeChipFilters}
						dimensions={dimensions.filter((dimension) => !project.hiddenDimensions.includes(dimension))}
					/>
				</div>
				<article className={cls(cardStyles.card, styles.graphCard)}>
					{activeMetric ? (
						<LineGraph
							data={graph}
							title={metricNames[reportMetric]}
							metric={reportMetric}
							range={range}
							isLoading={graphLoading}
							isUpdating={graphUpdating}
						/>
					) : (
						<div className={styles.emptyReport}>No metrics are visible for this project.</div>
					)}
				</article>
				<div className={styles.tables}>
					{activeMetric && pageDimensions.length > 0 && (
						<PageDimensionTabsCard dimensions={pageDimensions} query={query} onSelect={onSelectDimRow} />
					)}
					{activeMetric && campaignDimensions.length > 0 && (
						<DimensionDropdownCard dimensions={campaignDimensions} query={query} onSelect={onSelectDimRow} />
					)}
					{activeMetric && geoDimensions.includes("country") && (
						<GeoCard dimensions={geoDimensions} query={query} onSelect={onSelectDimRow} />
					)}
					{activeMetric && geoDimensions.length > 0 && !geoDimensions.includes("country") && (
						<DimensionTabsCard dimensions={geoDimensions} query={query} onSelect={onSelectDimRow} />
					)}
					{activeMetric && technologyDimensions.length > 0 && (
						<DimensionTabsCard dimensions={technologyDimensions} query={query} onSelect={onSelectDimRow} />
					)}
					{activeMetric && deviceDimensions.length > 0 && (
						<DimensionDropdownCard dimensions={deviceDimensions} query={query} onSelect={onSelectDimRow} />
					)}
					{activeMetric && !project.hiddenDimensions.includes("event") && (
						<EventsCard query={query} onSelect={onSelectDimRow} />
					)}
				</div>
			</Suspense>
		</div>
	);
};

const EventsCard = ({
	query,
	onSelect,
}: {
	query: ProjectQuery;
	onSelect: (value: DimensionTableRow, dimension: Dimension) => void;
}) => {
	// Session metrics aren't meaningful per custom event, so the card always reports a count metric.
	const eventMetric: Metric =
		query.metric === "bounce_rate" || query.metric === "avg_time_on_site" ? "views" : query.metric;
	const eventQuery = useMemo(() => ({ ...query, metric: eventMetric }), [query, eventMetric]);
	const { data, isLoading } = useDimension({ dimension: "event", ...eventQuery });
	// Keep the card mounted while loading so the grid doesn't jump; only hide it for projects with no custom events.
	if (!isLoading && (data?.length ?? 0) === 0) return null;

	return (
		<article className={cls(cardStyles.card, styles.eventsCard)} data-full-width="true">
			<div className={cardStyles.dimensionHeader}>
				<div>Events</div>
				<div>{metricNames[eventMetric]}</div>
			</div>
			<DimensionTable dimension="event" query={eventQuery} onSelect={(value) => onSelect(value, "event")} />
		</article>
	);
};

const GeoCard = ({
	dimensions,
	query,
	onSelect,
}: {
	dimensions: Dimension[];
	query: ProjectQuery;
	onSelect: (value: DimensionTableRow, dimension: Dimension) => void;
}) => {
	const { data } = useDimension({
		dimension: "country",
		...query,
	});

	return (
		<article className={cls(cardStyles.card, styles.geoCard, "geocard")} data-full-width="true">
			<div className={styles.geoMap}>
				<Suspense fallback={null}>
					<Worldmap data={data} metric={query.metric} />
				</Suspense>
			</div>
			<div className={styles.geoTable}>
				<DimensionTabs dimensions={dimensions} query={query} onSelect={onSelect} />
			</div>
		</article>
	);
};
