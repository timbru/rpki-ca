package nl.bruijnzeels.tim.rpki.ca.signer

import java.math.BigInteger
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import org.joda.time.Period
import nl.bruijnzeels.tim.rpki.ca.common.domain.CrlRequest
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import nl.bruijnzeels.tim.rpki.ca.common.domain.ManifestRequest
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningMaterial
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import nl.bruijnzeels.tim.rpki.ca.common.domain.Revocation

case class PublicationSet(number: BigInteger, mft: ManifestCms, crl: X509Crl, products: List[CertificateRepositoryObject] = List.empty) {

  import PublicationSet._

  def publish(caId: UUID, signingMaterial: SigningMaterial, products: List[CertificateRepositoryObject] = List.empty) = {

    val mftRevocation = Revocation.forCertificate(mft.getCertificate)
    val signingMaterialWithMftRevocation = signingMaterial.withNewRevocation(mftRevocation)
    val newSetNumber = number.add(BigInteger.ONE)

    val newCrl = createCrl(signingMaterialWithMftRevocation, newSetNumber)
    val newMft = createMft(signingMaterialWithMftRevocation, newSetNumber, products :+ newCrl)

    List(
      SignerAddedRevocation(caId, mftRevocation),
      SignerSignedCertificate(caId, newMft.getCertificate()),
      SignerUpdatedPublicationSet(caId, PublicationSet(newSetNumber, newMft, newCrl, products)))
  }

}

object PublicationSet {

  val CrlNextUpdate = Period.days(1)
  val MftNextUpdate = Period.days(1)
  val MftValidityTime = Period.days(7)

  def createFirst(caId: UUID, signingMaterial: SigningMaterial, products: List[CertificateRepositoryObject] = List.empty) = {
    val setNumber = BigInteger.ONE
    val crl = createCrl(signingMaterial, setNumber)
    val mft = createMft(signingMaterial, setNumber, products :+ crl)

    List(
      SignerSignedCertificate(caId, mft.getCertificate()),
      SignerUpdatedPublicationSet(caId, PublicationSet(setNumber, mft, crl, products)))
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