module Main where

import Network.TLS
import Network.TLS.Extra.Cipher
import Network.BSD
import Network.Socket

import Data.IORef
import Data.Char (isDigit)
import Data.Default.Class
import Data.X509 as X509
import Data.X509.Validation
import System.X509
import System.Hourglass
import Data.Hourglass.Types
import qualified Data.Hourglass as T

import Control.Exception (bracketOnError)
import System.Environment (getArgs)
import qualified Data.ByteString.Char8 as B

httpsPort :: Int
httpsPort = 443

-- Reference: https://github.comconnectvincenthz/hs-tls/blob/master/debug/src/RetrieveCertificate.hs

getCertificateChainFromRemote :: Network.Socket.HostName -> IO CertificateChain
getCertificateChainFromRemote s = do
    ref <- newIORef Nothing
    let params = (defaultParamsClient s $ B.pack $ show httpsPort)
                    { clientSupported = def { supportedCiphers = ciphersuite_all }
                    , clientShared    = def { sharedValidationCache = noValidate }
                    }
    he <- getHostByName s
    sock <- bracketOnError (socket AF_INET Stream defaultProtocol) sClose $ \sock -> do
            connect sock (SockAddrInet (fromIntegral $ httpsPort) (head $ hostAddresses he))
            return sock
    ctx <- contextNew sock params

    contextHookSetCertificateRecv ctx $ \l -> modifyIORef ref (const $ Just l)

    _   <- handshake ctx
    bye ctx
    r <- readIORef ref
    case r of
        Nothing    -> error "cannot retrieve any certificate"
        Just certs -> return certs
  where noValidate = ValidationCache (\_ _ _ -> return ValidationCachePass)
                                     (\_ _ _ -> return ())


diffDays :: DateTime -> DateTime -> Integer
diffDays x y = (fromIntegral $ T.timeDiff x y) `div` (24 * 3600)

main :: IO ()
main = do
  (host:_) <- getArgs
  (CertificateChain certs) <- getCertificateChainFromRemote host
  let expireTime = snd . certValidity . getCertificate $ head certs
  currentTime <- dateCurrent
  print $ diffDays expireTime currentTime
