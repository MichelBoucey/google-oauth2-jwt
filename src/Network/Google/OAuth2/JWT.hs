{-# LANGUAGE OverloadedStrings #-}

-- | Create a signed JWT needed to make the access token request
-- to gain access to Google APIs for server to server applications.
--
-- For all details : https://developers.google.com/identity/protocols/OAuth2ServiceAccount
--

module Network.Google.OAuth2.JWT where

import           Codec.Crypto.RSA.Pure
import qualified Data.ByteString            as B
import           Data.ByteString.Base64.URL (encode)
import           Data.ByteString.Lazy       (fromStrict, toStrict)
import           Data.Maybe                 (fromJust)
import           Data.Monoid                ((<>))
import qualified Data.Text                  as T
import           Data.Text.Encoding
import           Data.UnixTime              (getUnixTime, utSeconds)
import           Foreign.C.Types
import           OpenSSL.EVP.PKey           (toKeyPair)
import           OpenSSL.PEM                (PemPasswordSupply (PwNone),
                                             readPrivateKey)
import           OpenSSL.RSA

type Scope = T.Text

type Email = T.Text

-- |Get the private key obtained from
-- the Google API Console from a PEM file.
fromPEMFile :: FilePath -> IO PrivateKey
fromPEMFile f = readFile f >>= fromPEMString

-- |Get the private key obtained from
-- the Google API Console from a PEM 'String'.
fromPEMString :: String -> IO PrivateKey
fromPEMString s =
    fromJust . toKeyPair <$> readPrivateKey s PwNone
        >>= \k -> return $ PrivateKey
            { private_pub =
                  PublicKey { public_size = rsaSize k
                            , public_n    = rsaN k
                            , public_e    = rsaE k
                            }
            , private_d    = rsaD k
            , private_p    = rsaP k
            , private_q    = rsaQ k
            , private_dP   = 0
            , private_dQ   = 0
            , private_qinv = 0
            }

-- | Create the signed JWT ready for transmission
-- in the access token request as assertion value.
--
-- >grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=
--
getJWT :: Email
       -- ^ The email address of the service account.
       -> Maybe Email
       -- ^ The email address of the user for which the
       -- application is requesting delegated access.
       -> [Scope]
       -- ^The list of the permissions that the application requests.
       -> Maybe Int
       -- ^ Expiration time (maximun and default value is an hour, 3600).
       -> PrivateKey
       -- ^ The private key obtained from the Google API Console.
       -> IO (Either String B.ByteString)
       -- ^ Either an error message or a signed JWT.
getJWT iss msub scopes mexp privateKey = do
    let expt = fromIntegral $
                  case mexp of
                      Just e  -> e
                      Nothing -> 3600
    cs <- jwtClaimsSet
              (maybe T.empty (\s -> "\"sub\":\"" <> s <> "\",") msub) expt
    let i = jwtHeader <> "." <> cs
    return $ do
        if expt > 0 && expt <= 3600 then
            case rsassa_pkcs1_v1_5_sign hashSHA256 privateKey (fromStrict i) of
                Right s -> Right $ i <> "." <> (encode $ toStrict s)
                Left _  -> Left "RSAError"
                                    else Left "Bad expiration time"
  where
    jwtHeader = toJWT "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
    jwtClaimsSet s e = do
        (exp',iat') <-
            getUnixTime >>= \t ->
                return ( toText $ utSeconds t + CTime e
                       , toText $ utSeconds t
                       )
        return $ toJWT $
               "{\"iss\":\"" <> iss <> "\"," <> s <> "\"scope\":\""
            <> T.intercalate " " scopes <> "\",\"aud\":\"https://ww\
               \w.googleapis.com/oauth2/v4/token\",\"exp\":" <> exp'
            <> ",\"iat\":" <> iat' <> "}"
    toText = (T.pack . show)
    toJWT = (encode . encodeUtf8)

