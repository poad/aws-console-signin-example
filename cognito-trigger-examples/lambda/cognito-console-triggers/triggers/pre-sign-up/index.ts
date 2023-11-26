/* eslint-disable import/prefer-default-export */
import {
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminCreateUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  Callback,
  Context,
  PreSignUpTriggerEvent,
  PreSignUpTriggerHandler,
} from 'aws-lambda';

export const handler: PreSignUpTriggerHandler = async (
  event: PreSignUpTriggerEvent,
  _: Context,
  callback: Callback<any>
): Promise<any> => {
  // console.log(JSON.stringify(event));

  const { userPoolId, request, triggerSource } = event;

  if (triggerSource === 'PreSignUp_ExternalProvider') {
    const { userAttributes } = request;
    const { email } = userAttributes;

    const identityProvider = new CognitoIdentityProviderClient({});

    const user = (
      await identityProvider.send(
        new ListUsersCommand({
          UserPoolId: userPoolId,
          Filter: `email = "${email}"`,
        })
      )
    ).Users?.find(
      (u) => (u.UserStatus as string | undefined) !== 'EXTERNAL_PROVIDER'
    );

    // create a new user
    const targetUser =
      user ??
      (
        await identityProvider.send(
          new AdminCreateUserCommand({
            UserPoolId: userPoolId,
            Username: request.userAttributes.email,
            UserAttributes: Object.entries(request.userAttributes)
              .filter(
                (attr) =>
                  attr[0] !== 'cognito:email_alias' &&
                  attr[0] !== 'cognito:phone_number_alias'
              )
              .map((attr) => ({ Name: attr[0], Value: attr[1] })),
          })
        )
      ).User;
    if (!targetUser) {
      return callback('No such link target', event);
    }

    const provider = event.userName.split('_')[0];
    const identities: { [name: string]: string }[] = (
      targetUser.Attributes ?? []
    )
      .filter((attribute) => attribute.Name === 'identities' && attribute.Value)
      .flatMap(
        (attribute) =>
          JSON.parse(attribute.Value!) as { [name: string]: string }[]
      );
    if (
      !identities.find(
        (identity) =>
          identity.providerName && identity.providerName === provider
      )
    ) {
      return callback('No such link target', event);
    }
    // eslint-disable-next-line no-param-reassign
    event.response.autoVerifyEmail = true;
  }
  return callback(null, event);
};
