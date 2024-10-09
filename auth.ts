import NextAuth, { User } from "next-auth";
import { AdapterUser } from "next-auth/adapters";
import Google from "next-auth/providers/google";

declare module "next-auth" {
  interface User {
    idToken?: string;
  }
  interface Session {
    idToken?: string | undefined;
    accessToken?: string | undefined;
    
  }
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Google({
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          scope: "openid profile email",
          session: {
            strategy: "jwt",
          },
        },
      },
    }),
  ],
  callbacks: {
    // get the idToken
    async jwt({ token, account, user }) {
        console.log({token, account,user })
        // Initial sign in
        if (account && account.expires_in&& user) {
          return {
            accessToken: account.accessToken,
            accessTokenExpires: Date.now() + account.expires_in * 1000,
            refreshToken: account.refresh_token,
            idToken: account.id_token,
            user,
          }
        }

        // Return previous token if the access token has not expired yet
        if (Date.now() < (token.accessTokenExpires as number)) {
          console.log("Return previous token")
          return token
        }
  
        console.log("gonna refresh token")
        return refreshAccessToken(token)
        
        // Access token has expired, try to update it
      },
    async session({ session, token }) {
      if (token) {
        session.idToken = token.idToken as string;
        session.user = token.user as AdapterUser & User
        session.accessToken = token.accessToken as string
        // session.error = token.error
      }
      return session;
    },
  },
});

/**
 * Takes a token, and returns a new token with updated
 * `accessToken` and `accessTokenExpires`. If an error occurs,
 * returns the old token and an error property
 */
const   refreshAccessToken = async (token) => {
  try {
    const url =
      "https://oauth2.googleapis.com/token?" +
      new URLSearchParams({
        client_id: process.env.AUTH_GOOGLE_ID as string,
        client_secret: process.env.AUTH_GOOGLE_SECRET as string,
        grant_type: "refresh_token",
        refresh_token: token.refreshToken,
      })

    const response = await fetch(url, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
    })

    const refreshedTokens = await response.json()

    if (!response.ok) {
      throw refreshedTokens
    }

    return {
      ...token,
      accessToken: refreshedTokens.access_token,
      accessTokenExpires: Date.now() + refreshedTokens.expires_in * 1000,
      refreshToken: refreshedTokens.refresh_token ?? token.refreshToken, // Fall back to old refresh token
      idToken: refreshedTokens.id_token
    }
  } catch (error) {
    console.log(error)

    return {
      ...token,
      error: "RefreshAccessTokenError",
    }
  }
}