import {
  AdminLinkProviderForUserCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import type {
  Callback,
  Context,
  PostAuthenticationTriggerEvent,
  PostAuthenticationTriggerHandler,
} from 'aws-lambda';

export const handler: PostAuthenticationTriggerHandler = async (
  event: PostAuthenticationTriggerEvent,
  _: Context,
  callback: Callback<any>
): Promise<any> => {
  // console.log(JSON.stringify(event));

  const { userPoolId, request, triggerSource } = event;
  if (triggerSource === 'PostAuthentication_Authentication') {
    const identities = JSON.parse(request.userAttributes?.identities) || [];

    if (process.env.PROVIDERS !== undefined) {
      const providers = process.env.PROVIDERS.split(',').filter(
        (provider) =>
          identities.length === 0 ||
          identities.find(
            (identity?: { [name: string]: string }) =>
              identity?.providerName !== provider
          ) !== undefined
      );

      providers.forEach(async (provider) => {
        await new CognitoIdentityProviderClient({}).send(
          new AdminLinkProviderForUserCommand({
            UserPoolId: userPoolId,
            DestinationUser: {
              ProviderName: 'Cognito',
              ProviderAttributeValue: event.userName,
            },
            SourceUser: {
              ProviderName: provider,
              ProviderAttributeName: 'Cognito_Subject',
              ProviderAttributeValue: event.userName,
            },
          })
        );
      });
    }
  }

  callback(null, event);
};
