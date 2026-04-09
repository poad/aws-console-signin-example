import { useState, useEffect, useCallback } from 'react';
import { User } from '../interfaces';
import UserPoolClient from '../service/UserPoolClient';

export const useListUsers = (client: UserPoolClient) => {
  const [state, setState] = useState<{
    data?: User[];
    error?: Error;
    loaded: boolean;
  }>({ loaded: false });

  const loadUsers = useCallback(async () =>
    client
      .listUsers()
      .then((items) =>
        setState({
          data: items.map(
            ({
              username,
              attributes,
              createdAt,
              lastModifiedAt,
              enabled,
              status,
              mfa,
            }) => {
              const { email } = attributes;
              return {
                username,
                attributes,
                createdAt,
                lastModifiedAt,
                enabled,
                status,
                mfa,
                email,
              } as User;
            },
          ),
          loaded: true,
        }),
      )
      .catch((error) => setState({ error, loaded: false })),
  [client]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  return {
    users: state.data,
    error: state.error,
    loaded: state.loaded,
    setUsers: (newUsers?: User[]) => setState({ ...state, data: newUsers }),
    clearError: () => setState({ ...state, error: undefined }),
    reload: loadUsers,
  };
};
