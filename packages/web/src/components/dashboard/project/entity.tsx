import styles from "./entity.module.css";

import type { ProjectResponse } from "@/constants";

export const SelectEntity = ({
	entities,
	value,
	onChange,
}: {
	entities: ProjectResponse["entities"];
	value?: string;
	onChange: (entityId?: string) => void;
}) => {
	return (
		<select
			className={styles.entitySelect}
			value={value ?? ""}
			onChange={(e) => onChange(e.target.value || undefined)}
			aria-label="Filter by entity"
		>
			<option value="">All entities</option>
			{entities.map((entity) => (
				<option key={entity.id} value={entity.id}>
					{entity.displayName}
				</option>
			))}
		</select>
	);
};
