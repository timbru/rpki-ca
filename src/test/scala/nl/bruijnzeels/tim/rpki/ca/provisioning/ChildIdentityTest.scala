package nl.bruijnzeels.tim.rpki.ca.provisioning

import org.scalatest.Matchers
import org.scalatest.FunSuite

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ChildIdentityTest extends FunSuite with Matchers {

  val childXml = "<ns0:identity xmlns:ns0=\"http://www.hactrn.net/uris/rpki/myrpki/\" handle=\"Bob\" version=\"2\">\n" +
    "<ns0:bpki_ta>\n" +
    "MIIDIDCCAgigAwIBAgIBATANBgkqhkiG9w0BAQsFADApMScwJQYDVQQDEx5Cb2Ig\n" +
    "QlBLSSBSZXNvdXJjZSBUcnVzdCBBbmNob3IwHhcNMTEwNzAxMDQwNzIzWhcNMTIw\n" +
    "NjMwMDQwNzIzWjApMScwJQYDVQQDEx5Cb2IgQlBLSSBSZXNvdXJjZSBUcnVzdCBB\n" +
    "bmNob3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEk1f7cVzHu3r/\n" +
    "fJ5gkBxnWMNJ1CP0kPtfP8oFOEVVH1lX0MHuFKhdKA4WCkGkeFtGb/4T/nGgsD+z\n" +
    "exZid6RR8zjHkwMLvAl0x6wdKa46XJbFu+wTSu+vlowVY9rGzH+ttv4Fj6E2Y3DG\n" +
    "983/dVNJfXl00+Ts7rlvVcn9lI5dWvzsLoUOdhD4hsyKp53k8i4HexiD+0ugPeh9\n" +
    "4PKiyZOuMjSRNQSBUA3ElqJSRZz7nWvs/j6zhwHdFa+lN56575Mc5mrwr+KePwW5\n" +
    "DLt3izYpjwKffVuxUKPTrhvnOOg5kBBv0ihync21LSLds6jusxaMYUwUElO8KQyn\n" +
    "NUAeGPd/AgMBAAGjUzBRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFORFOC3G\n" +
    "PjYKn7V1/BJHDmZ4W7J+MB8GA1UdIwQYMBaAFORFOC3GPjYKn7V1/BJHDmZ4W7J+\n" +
    "MA0GCSqGSIb3DQEBCwUAA4IBAQBqsP4ENtWTkNdsekYB+4hO/Afq20Ho0W8lyTkM\n" +
    "JO1UFDt/dzFAmTT4uM7pmwuQfqmCYjNDWon8nsdFno4tA0is3aiq6yIMAYzBE5ub\n" +
    "bnJMxldqLoWuakco1wYa3kZFzWPwecxgJ4ZlqTPGu0Loyjibt25IE9MfixyWDw+D\n" +
    "MhyfonLLgFb5jz7A3BTE63vlTp359uDbFb1nRdyoT31s3FUBK8jF4B5pWzPiLdct\n" +
    "bOMVjYUBs8aFC3fDXyGSr/RcjE4OOZQyTkYZn8zCPUJ4KqOPAUV9u9jx2FPvOcA3\n" +
    "1BjcmhYHqott+cnK1ITOjLe9EKejRZv/7/BFsmpzm2Zbq1KA\n" +
    "</ns0:bpki_ta>\n" +
    "</ns0:identity>\n"
    
  test("Should create child ID from xml") {
    val id = ChildIdentity.fromXml(childXml)
  }

}