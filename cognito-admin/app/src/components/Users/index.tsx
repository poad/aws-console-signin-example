import { useListUsers } from '../../hooks/useListUsers';
import { Page } from '../../hooks/usePagenationTable';
import { useUser } from '../../hooks/useUser';
import { User } from '../../interfaces';
import UserPoolClient from '../../service/UserPoolClient';
import CreateUserDialog from '../CreateUserDialog';
import ErrorDialog from '../ErrorDialog';
import LoadingSpinner from '../styled/LoadingSpinner';
import UserDetail from '../UserDetail';
import UsersTable from './UsersTable';
/* oxlint-disable react/react-in-jsx-scope */
import { Container, Box } from '@mui/material';
import { JSX, useState, Fragment } from 'react';

interface UsersProps {
  /**
   * Injected by the documentation to work in an iframe.
   * You won't need it on your project.
   */
  container?: Element;
  client: UserPoolClient;
  page: Page;
}

const Users = ({ client, page: initPage }: UsersProps): JSX.Element => {
  const [openDetail, setOpenDetail] = useState<boolean>(false);

  const { users, error, loaded, setUsers, clearError } = useListUsers(client);

  const { user, setUser, loadUser } = useUser(client);

  const openUserDetail = (origin: User) => {
    loadUser(origin);
    setOpenDetail(true);
  };

  const backdropClose = () => clearError();

  const handleCloseDetail = () => {
    setOpenDetail(false);
  };

  const onCreate = (newUser: User) => {
    setUsers(users?.concat(newUser) || [newUser]);
  };

  const onUpdate = (newUser: User) => {
    setUser(newUser);
    if (users?.find((item) => item.email === newUser.email)) {
      setUsers(
        users?.filter((item) => item.email !== newUser.email)?.concat(newUser),
      );
    }
  };

  const onDelete = (target: User) => {
    setUsers(users?.filter((u) => u.email !== target.email));
  };

  return (
    <Fragment>
      <LoadingSpinner expose={!loaded && !error} />
      <ErrorDialog
        id='alert-dialog'
        open={error != undefined}
        message={JSON.stringify(error)}
        onClose={backdropClose}
      />

      {user ? (
        <UserDetail
          client={client}
          user={user}
          open={openDetail}
          onClose={handleCloseDetail}
          onUpdate={onUpdate}
          onDelete={onDelete}
        />
      ) : (
        ''
      )}

      <Box sx={{ m: 1 }}>
        <Container fixed>
          <CreateUserDialog client={client} onCreate={onCreate} />
          {users ? (
            <UsersTable
              users={users}
              initPage={initPage}
              onClick={openUserDetail}
            />
          ) : (
            <></>
          )}
        </Container>
      </Box>
    </Fragment>
  );
};

export default Users;
