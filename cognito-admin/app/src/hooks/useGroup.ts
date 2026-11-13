import { Group } from '../interfaces';
import UserPoolClient from '../service/UserPoolClient';
import { useState, useCallback } from 'react';

export const useGroup = (
  client: UserPoolClient,
): { group?: Group; loadGroup: (origin: Group) => void } => {
  const [group, setGroup] = useState<Group | undefined>(undefined);
  const loadGroup = useCallback(
    async (origin: Group) => {
      const users = await client.listUsersInGroup(origin.groupName);
      setGroup({ ...origin, users });
    },
    [client],
  );
  return { group, loadGroup };
};
