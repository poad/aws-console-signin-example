import { JSX, useState } from 'react';
import { Box, CssBaseline } from '@mui/material';
import { Amplify } from 'aws-amplify';
import { useAuthenticator, withAuthenticator } from '@aws-amplify/ui-react';
import '@aws-amplify/ui-react/styles.css';

import styles from '../styles/Home.module.css';
import awsconfig, { appConfig } from '../aws-config';
import Users from '../components/Users';
import TabPanel from '../components/TabPanel';
import Groups from '../components/Groups';
import React from 'react';
import IamClient, { ICredentials } from '../service/IamClient';
import UserPoolClient from '../service/UserPoolClient';
import LoadingSpinner from '../components/styled/LoadingSpinner';
import { ErrorDialogProps } from '../interfaces';
import ErrorDialog from '../components/ErrorDialog';
import { Header } from '../components/Header';
import { fetchAuthSession } from 'aws-amplify/auth';

Amplify.configure(awsconfig);

interface HomeProps {
  signOut: (opts?: any) => Promise<any>;
}

function Home(props?: HomeProps): JSX.Element {
  const { authStatus } = useAuthenticator((context) => [context.authStatus]);
  const [state, setState] = useState<{
    data?: {
      credentials: ICredentials;
      client: UserPoolClient;
      iamClient: IamClient;
    };
    error?: Error;
    loaded: boolean;
  }>({ loaded: false });

  const [errorDialog, setErrorDialog] = useState<ErrorDialogProps>({
    open: false,
  });
  if (authStatus === 'authenticated') {
    fetchAuthSession()
      .then((session) => {
        if (session.credentials) {
          const credentials = {
            ...session.credentials,
            sessionToken: session.credentials.sessionToken ?? '',
            authenticated: true,
            identityId: '',
          };
          setState({
            data: {
              credentials,
              client: new UserPoolClient(
                credentials,
                appConfig.endUserPoolId,
                appConfig.region
              ),
              iamClient: new IamClient(credentials, appConfig.region),
            },
            loaded: true,
          });
        }
      })
      .catch((error) => setState({ error, loaded: false }));
  }

  const [tab, setTab] = useState<number>(0);

  const endpoint = process.env.NEXT_PUBLIC_AWS_COGNITO_OAUTH_DOMAIN_CONSOLE;
  const idp =
    process.env.NEXT_PUBLIC_AWS_COGNITO_IDENTITY_PROVIDER !== undefined
      ? `identity_provider=${process.env.NEXT_PUBLIC_AWS_COGNITO_IDENTITY_PROVIDER}&`
      : '';
  const redirect = process.env.NEXT_PUBLIC_SIGN_IN_ENDPOINT;
  const clientId = process.env.NEXT_PUBLIC_AWS_WEB_CLIENT_ID_CONSOLE;
  const scopes = process.env.NEXT_PUBLIC_SCOPES;

  const { signOut } = props ? props : { signOut: () => {} };

  const consoleUrl = `${endpoint}/oauth2/authorize?${idp}redirect_uri=${redirect}&response_type=CODE&client_id=${clientId}&scope=${scopes}`;

  const handleChange = (
    _event: React.SyntheticEvent<Element, Event>,
    newValue: number
  ) => {
    setTab(newValue);
  };

  return (
    <React.Fragment>
      <LoadingSpinner expose={!state.loaded} />
      <ErrorDialog
        open={errorDialog.open}
        message={errorDialog.message}
        onClose={() => setErrorDialog({ open: false })}
      />

      <Box sx={{ display: 'flex', color: '#fff' }}>
        <Box className={styles.main}>
          <CssBaseline />
          <Header
            tab={tab}
            handleChange={handleChange}
            consoleUrl={consoleUrl}
            signOut={signOut}
          />
          {state.data ? (
            <>
              <TabPanel value={tab} index={0}>
                <Users
                  client={state.data.client}
                  page={{ page: 0, rowsPerPage: 10 }}
                />
              </TabPanel>
              <TabPanel value={tab} index={1}>
                <Groups
                  client={state.data.client}
                  iamClient={state.data.iamClient}
                  page={{ page: 0, rowsPerPage: 10 }}
                />
              </TabPanel>
            </>
          ) : (
            <></>
          )}
        </Box>
      </Box>
    </React.Fragment>
  );
}

export default withAuthenticator<HomeProps>(Home);
