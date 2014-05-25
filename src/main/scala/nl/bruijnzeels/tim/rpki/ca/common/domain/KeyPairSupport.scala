package nl.bruijnzeels.tim.rpki.ca.common.domain

import java.security.KeyPair

import net.ripe.rpki.commons.crypto.util.KeyPairFactory

object KeyPairSupport {

  val DefaultSignatureProvider = "SunRsaSign"

  def createRpkiKeyPair(): KeyPair = {
    new KeyPairFactory(DefaultSignatureProvider).generate()
  }

}
