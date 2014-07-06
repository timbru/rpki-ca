package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger
import java.util.UUID

import org.joda.time.Period

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl

import common.domain.CrlRequest
import common.domain.ManifestRequest
import common.domain.Revocation
import common.domain.SigningMaterial
import common.domain.SigningSupport

case class PublicationSet(number: BigInteger, mft: ManifestCms, crl: X509Crl, products: List[CertificateRepositoryObject] = List.empty) {

  import PublicationSet._

  def publish(caId: UUID, resourceClassName: String, signingMaterial: SigningMaterial, products: List[CertificateRepositoryObject] = List.empty) = {

    val mftRevocation = Revocation.forCertificate(mft.getCertificate)
    val signingMaterialWithMftRevocation = signingMaterial.withNewRevocation(mftRevocation)
    val newSetNumber = number.add(BigInteger.ONE)

    val newCrl = createCrl(signingMaterialWithMftRevocation, newSetNumber)
    val newMft = createMft(signingMaterialWithMftRevocation, newSetNumber, products :+ newCrl)

    List(
      SignerAddedRevocation(caId, resourceClassName, mftRevocation),
      SignerSignedCertificate(caId, resourceClassName, newMft.getCertificate()),
      SignerUpdatedPublicationSet(caId, resourceClassName, PublicationSet(newSetNumber, newMft, newCrl, products)))
  }

}

object PublicationSet {

  val CrlNextUpdate = Period.days(1)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)

  def createFirst(caId: UUID, resourceClassName: String, signingMaterial: SigningMaterial, products: List[CertificateRepositoryObject] = List.empty) = {
    val setNumber = BigInteger.ONE
    val crl = createCrl(signingMaterial, setNumber)
    val mft = createMft(signingMaterial, setNumber, products :+ crl)

    List(
      SignerSignedCertificate(caId, resourceClassName, mft.getCertificate()),
      SignerUpdatedPublicationSet(caId, resourceClassName, PublicationSet(setNumber, mft, crl, products)))
  }

  def createCrl(signingMaterial: SigningMaterial, setNumber: BigInteger) = {
    val crlRequest = CrlRequest(nextUpdateDuration = CrlNextUpdate, crlNumber = setNumber, revocations = signingMaterial.revocations)
    SigningSupport.createCrl(signingMaterial, crlRequest)
  }

  def createMft(signingMaterial: SigningMaterial, setNumber: BigInteger, publishedObjects: List[CertificateRepositoryObject]) = {
    val mftRequest = ManifestRequest(nextUpdateDuration = MftNextUpdate,
      validityDuration = MftValidityTime,
      manifestNumber = setNumber,
      publishedObjects = publishedObjects,
      certificateSerial = signingMaterial.lastSerial.add(BigInteger.ONE))
    SigningSupport.createManifest(signingMaterial, mftRequest)
  }

}