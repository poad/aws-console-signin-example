import * as iam from 'aws-cdk-lib/aws-iam';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as cdk from 'aws-cdk-lib';
import * as awslogs from 'aws-cdk-lib/aws-logs';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as idp from '@aws-sdk/client-cognito-identity-provider';
import { Construct } from 'constructs';

export interface InfraStackStackProps extends cdk.StackProps {
  adminUserPool: string;
  endUserPool: string;
  region: string;
  environment: string;
  domain: string;
  endUserDomain: string;
  provider: string;
  lambda: {
    app: {
      userMaagement: {
        name: string;
        entry: string;
      };
    };
  };
  groupRoleClassificationTag: {
    name: string | undefined;
    value: string | undefined;
  };
  testRoles: number | undefined;
}

export class InfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: InfraStackStackProps) {
    super(scope, id, props);

    const {
      adminUserPool: adminUserPoolName,
      endUserPool: endUserPoolName,
      region,
      environment,
      domain,
      endUserDomain,
      provider,
      groupRoleClassificationTag,
      testRoles,
    } = props;

    const signInFn = new nodejs.NodejsFunction(this, 'SignInLambdaFunction', {
      runtime: lambda.Runtime.NODEJS_24_X,
      entry: 'lambda/signin/index.ts',
      functionName: `${environment}-cognito-admin-user-console-sign-in`,
      logRetention: awslogs.RetentionDays.ONE_DAY,
      retryAttempts: 0,
      environment: {
        DOMAIN: endUserDomain,
        REGION: region,
      },
      role: new iam.Role(this, 'SignInLambdaExecutionRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        inlinePolicies: {
          'logs-policy': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'logs:CreateLogGroup',
                  'logs:CreateLogStream',
                  'logs:PutLogEvents',
                ],
                resources: [
                  `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/${environment}-cognito-admin-user-console-sign-in:*`,
                ],
              }),
            ],
          }),
          'assumed-role-policy': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'cognito-identity:*',
                  'cognito-idp:*',
                  'sts:GetFederationToken',
                  'sts:AssumeRoleWithWebIdentity',
                ],
                resources: ['*'],
              }),
            ],
          }),
        },
      }),
    });

    const signOutFn = new nodejs.NodejsFunction(this, 'SignOutLambdaFunction', {
      runtime: lambda.Runtime.NODEJS_24_X,
      entry: 'lambda/signout/index.ts',
      functionName: `${environment}-cognito-admin-user-console-sign-out`,
      logRetention: awslogs.RetentionDays.ONE_DAY,
      retryAttempts: 0,
      role: new iam.Role(this, 'SignOutLambdaExecutionRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        inlinePolicies: {
          'logs-policy': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'logs:CreateLogGroup',
                  'logs:CreateLogStream',
                  'logs:PutLogEvents',
                ],
                resources: [
                  `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/${environment}-cognito-admin-user-console-sign-out:*`,
                ],
              }),
            ],
          }),
          'assumed-role-policy': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'cognito-identity:*',
                  'cognito-idp:*',
                  'sts:GetFederationToken',
                  'sts:AssumeRoleWithWebIdentity',
                ],
                resources: ['*'],
              }),
            ],
          }),
        },
      }),
    });

    const api = new apigatewayv2.HttpApi(this, 'HttpApi', {
      apiName: `Cognito Console Lambda API (${environment})`,
      defaultIntegration: new integrations.HttpLambdaIntegration(
        'default-handler',
        signInFn
      ),
    });
    api.addRoutes({
      path: '/signin',
      methods: [apigatewayv2.HttpMethod.GET, apigatewayv2.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('signin-handler', signInFn),
    });

    api.addRoutes({
      path: '/signout',
      methods: [apigatewayv2.HttpMethod.GET, apigatewayv2.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('signout-handler', signOutFn),
    });

    const blockExternalUserFn = new nodejs.NodejsFunction(
      this,
      'BlockExternalUserLambdaFunction',
      {
        runtime: lambda.Runtime.NODEJS_24_X,
        entry: 'lambda/block-external-user/index.ts',
        functionName: `${environment}-cognito-admin-block-external-user`,
        logRetention: awslogs.RetentionDays.ONE_DAY,
        retryAttempts: 0,
        role: new iam.Role(this, 'BlockExternalUserExecutionRole', {
          assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
          inlinePolicies: {
            'logs-policy': new iam.PolicyDocument({
              statements: [
                new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: [
                    'logs:CreateLogGroup',
                    'logs:CreateLogStream',
                    'logs:PutLogEvents',
                  ],
                  resources: [
                    `arn:aws:logs:${region}:${this.account}:log-group:/aws/lambda/${environment}-cognito-admin-block-external-user`,
                    `arn:aws:logs:${region}:${this.account}:log-group:/aws/lambda/${environment}-cognito-admin-block-external-user:*`,
                  ],
                }),
              ],
            }),
            'assumed-role-policy': new iam.PolicyDocument({
              statements: [
                new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: ['cognito-identity:*', 'cognito-idp:*'],
                  resources: ['*'],
                }),
              ],
            }),
          },
        }),
      }
    );

    const endUserPool = new cognito.UserPool(this, endUserPoolName, {
      userPoolName: endUserPoolName,
      signInAliases: {
        username: true,
        email: true,
        preferredUsername: false,
        phone: false,
      },
      autoVerify: {
        email: true,
        phone: false,
      },
      standardAttributes: {
        email: {
          required: true,
        },
        preferredUsername: {
          required: false,
        },
        phoneNumber: {
          required: false,
        },
      },
      enableSmsRole: false,
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      passwordPolicy: {
        minLength: 6,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      lambdaTriggers: {
        preSignUp: blockExternalUserFn,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    endUserPool.addDomain('EndUserPoolDomain', {
      cognitoDomain: {
        domainPrefix: endUserDomain,
      },
    });

    const addAdminUserFn = new nodejs.NodejsFunction(
      this,
      'AddAdminUserLambdaFunction',
      {
        runtime: lambda.Runtime.NODEJS_24_X,
        entry: 'lambda/add-admin-user/index.ts',
        functionName: `${environment}-cognito-admin-add-admin-user`,
        logRetention: awslogs.RetentionDays.ONE_DAY,
        retryAttempts: 0,
        environment: {
          DEST_USER_POOL_ID: endUserPool.userPoolId,
          PROVIDER: provider,
        },
        role: new iam.Role(this, 'AddAdminUserExecutionRole', {
          assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
          inlinePolicies: {
            'logs-policy': new iam.PolicyDocument({
              statements: [
                new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: [
                    'logs:CreateLogGroup',
                    'logs:CreateLogStream',
                    'logs:PutLogEvents',
                  ],
                  resources: [
                    `arn:aws:logs:${region}:${this.account}:log-group:/aws/lambda/${environment}-cognito-admin-add-admin-user`,
                    `arn:aws:logs:${region}:${this.account}:log-group:/aws/lambda/${environment}-cognito-admin-add-admin-user:*`,
                  ],
                }),
              ],
            }),
            'assumed-role-policy': new iam.PolicyDocument({
              statements: [
                new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: ['cognito-identity:*', 'cognito-idp:*'],
                  resources: ['*'],
                }),
              ],
            }),
          },
        }),
      }
    );

    const adminUserPool = new cognito.UserPool(this, adminUserPoolName, {
      userPoolName: adminUserPoolName,
      signInAliases: {
        username: true,
        email: true,
        preferredUsername: false,
        phone: false,
      },
      autoVerify: {
        email: true,
      },
      standardAttributes: {
        email: {
          required: true,
        },
        preferredUsername: {
          required: false,
        },
        phoneNumber: {
          required: false,
        },
      },
      enableSmsRole: false,
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: {
        sms: false,
        otp: true,
      },
      passwordPolicy: {
        minLength: 6,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      lambdaTriggers: {
        postAuthentication: addAdminUserFn,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    adminUserPool.addDomain('AdminnUserPoolDomain', {
      cognitoDomain: {
        domainPrefix: domain,
      },
    });

    const adminPoolClient = new cognito.UserPoolClient(this, 'AdminPoolAppClient', {
      userPool: adminUserPool,
      userPoolClientName: `${environment}-admin-user-pool-client`,
      authFlows: {
        adminUserPassword: true,
        userSrp: true,
        userPassword: true,
        custom: true,
      },
      oAuth: {
        callbackUrls: [
          'http://localhost:3000',
          `https://${endUserDomain}.auth.${region}.amazoncognito.com/oauth2/idpresponse`,
        ],
        // logoutUrls,
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: true,
        },
        scopes: [
          cognito.OAuthScope.COGNITO_ADMIN,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
        ],
      },
      preventUserExistenceErrors: true,
    });

    const adminPoolIdentityPool = new cognito.CfnIdentityPool(this, 'AdminIdPool', {
      allowUnauthenticatedIdentities: false,
      cognitoIdentityProviders: [
        {
          clientId: adminPoolClient.userPoolClientId,
          providerName: adminUserPool.userPoolProviderName,
          serverSideTokenCheck: true,
        },
      ],
      identityPoolName: `${environment} admin users`,
    });

    const adminUnauthenticatedRole = new iam.Role(
      this,
      'AdminCognitoDefaultUnauthenticatedRole',
      {
        roleName: `${environment}-cognito-admin-users-unauth-role`,
        assumedBy: new iam.FederatedPrincipal(
          'cognito-identity.amazonaws.com',
          {
            StringEquals: {
              'cognito-identity.amazonaws.com:aud': adminPoolIdentityPool.ref,
            },
            'ForAnyValue:StringLike': {
              'cognito-identity.amazonaws.com:amr': 'unauthenticated',
            },
          },
          'sts:AssumeRoleWithWebIdentity'
        ),
        inlinePolicies: {
          'allow-assume-role': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'cognito-identity:*',
                  'cognito-idp:*',
                  'sts:GetFederationToken',
                  'sts:AssumeRoleWithWebIdentity',
                ],
                resources: ['*'],
              }),
            ],
          }),
        },
      }
    );

    const adminAuthenticatedRole = new iam.Role(
      this,
      'AdminCognitoDefaultAuthenticatedRole',
      {
        roleName: `${environment}-cognito-admin-users-auth-role`,
        assumedBy: new iam.FederatedPrincipal(
          'cognito-identity.amazonaws.com',
          {
            StringEquals: {
              'cognito-identity.amazonaws.com:aud': adminPoolIdentityPool.ref,
            },
            'ForAnyValue:StringLike': {
              'cognito-identity.amazonaws.com:amr': 'authenticated',
            },
          },
          'sts:AssumeRoleWithWebIdentity'
        ),
        maxSessionDuration: cdk.Duration.hours(12),
        inlinePolicies: {
          'allow-assume-role': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'cognito-identity:*',
                  'cognito-idp:*',
                  'sts:GetFederationToken',
                  'sts:AssumeRoleWithWebIdentity',
                  'iam:ListRoles',
                  'iam:PassRole',
                  'iam:GetRole',
                ],
                resources: ['*'],
              }),
            ],
          }),
        },
      }
    );

    new cognito.CfnIdentityPoolRoleAttachment(this, 'AdminIdPoolRoleAttachment', {
      identityPoolId: adminPoolIdentityPool.ref,
      roles: {
        authenticated: adminAuthenticatedRole.roleArn,
        unauthenticated: adminUnauthenticatedRole.roleArn,
      },
    });

    const cfnIdp = new cognito.CfnUserPoolIdentityProvider(this, 'OIDCProvider', {
      providerName: provider,
      providerType: idp.IdentityProviderTypeType.OIDC,
      userPoolId: endUserPool.userPoolId,
      providerDetails: {
        client_id: adminPoolClient.userPoolClientId,
        authorize_scopes: 'email openid profile',
        oidc_issuer: `https://cognito-idp.${region}.amazonaws.com/${adminUserPool.userPoolId}`,
        attributes_request_method: 'GET',
      },
      attributeMapping: {
        email: 'email',
      },
    });

    cfnIdp.node.addDependency(adminPoolClient, endUserPool);

    const endUsersClient = new cognito.UserPoolClient(this, 'EndUserPoolAppClient', {
      userPool: endUserPool,
      userPoolClientName: `${environment}-end-user-pool-client`,
      authFlows: {
        adminUserPassword: true,
        userSrp: true,
        userPassword: true,
        custom: true,
      },
      oAuth: {
        callbackUrls: ['http://localhost:3000', `${api.url}signin`],
        logoutUrls: [`${api.url}signout`],
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: true,
        },
        scopes: [
          cognito.OAuthScope.COGNITO_ADMIN,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
        ],
      },
      preventUserExistenceErrors: true,
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO,
        cognito.UserPoolClientIdentityProvider.custom(cfnIdp.providerName),
      ],
    });

    endUsersClient.node.addDependency(endUserPool, cfnIdp);

    const endUserPoolIdentityPool = new cognito.CfnIdentityPool(this, 'EndUserIdPool', {
      allowUnauthenticatedIdentities: false,
      allowClassicFlow: true,
      cognitoIdentityProviders: [
        {
          clientId: endUsersClient.userPoolClientId,
          providerName: endUserPool.userPoolProviderName,
          serverSideTokenCheck: true,
        },
      ],
      identityPoolName: `${environment} end users`,
    });

    const endUserUnauthenticatedRole = new iam.Role(
      this,
      'EndUserCognitoDefaultUnauthenticatedRole',
      {
        roleName: `${environment}-cognito-end-users-unauth-role`,
        assumedBy: new iam.FederatedPrincipal(
          'cognito-identity.amazonaws.com',
          {
            StringEquals: {
              'cognito-identity.amazonaws.com:aud': endUserPoolIdentityPool.ref,
            },
            'ForAnyValue:StringLike': {
              'cognito-identity.amazonaws.com:amr': 'unauthenticated',
            },
          },
          'sts:AssumeRoleWithWebIdentity'
        ),
        inlinePolicies: {
          'allow-assume-role': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'cognito-identity:*',
                  'cognito-idp:*',
                  'sts:GetFederationToken',
                  'sts:AssumeRoleWithWebIdentity',
                ],
                resources: ['*'],
              }),
            ],
          }),
        },
      }
    );

    const endUserAuthenticatedRole = new iam.Role(
      this,
      'EndUserCognitoDefaultAuthenticatedRole',
      {
        roleName: `${environment}-cognito-end-users-auth-role`,
        assumedBy: new iam.FederatedPrincipal(
          'cognito-identity.amazonaws.com',
          {
            StringEquals: {
              'cognito-identity.amazonaws.com:aud': endUserPoolIdentityPool.ref,
            },
            'ForAnyValue:StringLike': {
              'cognito-identity.amazonaws.com:amr': 'authenticated',
            },
          },
          'sts:AssumeRoleWithWebIdentity'
        ).withSessionTags(),
        maxSessionDuration: cdk.Duration.hours(12),
        inlinePolicies: {
          'allow-assume-role': new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                  'cognito-identity:*',
                  'cognito-idp:*',
                  'sts:GetFederationToken',
                  'sts:AssumeRoleWithWebIdentity',
                ],
                resources: ['*'],
              }),
            ],
          }),
        },
      }
    );

    new cognito.CfnIdentityPoolRoleAttachment(this, 'EndUsersIdPoolRoleAttachment', {
      identityPoolId: endUserPoolIdentityPool.ref,
      roles: {
        authenticated: endUserAuthenticatedRole.roleArn,
        unauthenticated: endUserUnauthenticatedRole.roleArn,
      },
    });

    if (testRoles !== undefined && testRoles > 0) {
      const range = [...Array(testRoles).keys()];
      range.forEach((i) => {
        const roleName = `${environment}-test-group-role-${i + 1}`;

        const groupRole = new iam.Role(this, `TestGroupRole${i + 1}`, {
          roleName,
          assumedBy: new iam.FederatedPrincipal(
            'cognito-identity.amazonaws.com',
            {
              StringEquals: {
                'cognito-identity.amazonaws.com:aud':
                  endUserPoolIdentityPool.ref,
              },
              'ForAnyValue:StringLike': {
                'cognito-identity.amazonaws.com:amr': 'authenticated',
              },
            },
            'sts:AssumeRoleWithWebIdentity'
          ),
          maxSessionDuration: cdk.Duration.hours(12),
          inlinePolicies: {
            'allow-assume-role': new iam.PolicyDocument({
              statements: [
                new iam.PolicyStatement({
                  effect: iam.Effect.ALLOW,
                  actions: [
                    'cognito-identity:*',
                    'cognito-idp:*',
                    'sts:GetFederationToken',
                    'sts:AssumeRoleWithWebIdentity',
                  ],
                  resources: ['*'],
                }),
              ],
            }),
          },
        });

        signInFn.addEnvironment('USER_POOL_ID', endUserPool.userPoolId);
        signInFn.addEnvironment('CLIENT_ID', endUsersClient.userPoolClientId);
        signInFn.addEnvironment('ID_POOL_ID', endUserPoolIdentityPool.ref);
        signInFn.addEnvironment(
          'IDENTITY_PROVIDER',
          endUserPool.userPoolProviderName
        );
        signInFn.addEnvironment('API_URL', api.url!);

        if (
          groupRoleClassificationTag.name !== undefined &&
          groupRoleClassificationTag.value !== undefined
        ) {
          cdk.Tags.of(groupRole).add(
            groupRoleClassificationTag.name,
            groupRoleClassificationTag.value
          );
        }
      });
    }
  }
}
