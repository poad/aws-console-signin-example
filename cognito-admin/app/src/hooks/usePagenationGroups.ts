import { useState, useEffect, useCallback } from 'react';
import UserPoolClient from '../service/UserPoolClient';
import { Group } from '../interfaces';

export const usePagenationGroups = (
  client: UserPoolClient,
): {
  groups?: Group[];
  error?: Error;
  loaded: boolean;
  create: (group: Group) => void;
  delete: (group: Group) => void;
  update: (groups: Group[]) => void;
  clearError: () => void;
} => {
  const [state, setState] = useState<{
    data?: Group[];
    error?: Error;
    loaded: boolean;
  }>({ loaded: false });

  const loadGroups = useCallback(async () =>
    client
      .listGroups()
      .then((items) =>
        setState({
          data: items,
          loaded: true,
        }),
      )
      .catch((error) => setState({ error, loaded: false })),
  [client]);

  useEffect(() => {
    loadGroups();
  }, [loadGroups]);

  return {
    groups: state.data,
    error: state.error,
    loaded: state.loaded,
    create: (group: Group) =>
      setState({
        ...state,
        data: state.data ? state.data.concat(group) : [group],
      }),
    delete: (target: Group) => {
      const groups = state.data;
      if (groups) {
        const newGroups = groups.filter(
          (group) => group.groupName !== target.groupName,
        );
        if (newGroups) {
          setState({ ...state, data: newGroups });
        }
      }
    },
    update: (newGroups: Group[]) => setState({ ...state, data: newGroups }),
    clearError: () => setState({ ...state, error: undefined }),
  };
};
