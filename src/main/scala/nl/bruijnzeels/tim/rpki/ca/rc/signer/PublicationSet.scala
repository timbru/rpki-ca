package nl.bruijnzeels.tim.rpki
package ca
package rc
package signer

import java.math.BigInteger
import java.net.URI
import java.util.UUID

import scala.annotation.migration

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import nl.bruijnzeels.tim.rpki.ca.common.domain.RpkiObjectNameSupport
import nl.bruijnzeels.tim.rpki.publication.messages.Publish
import nl.bruijnzeels.tim.rpki.publication.messages.ReferenceHash
import nl.bruijnzeels.tim.rpki.publication.messages.Withdraw

case class PublicationSet(number: BigInteger, items: Map[ReferenceHash, CertificateRepositoryObject] = Map.empty, mft: Option[ManifestCms] = None, crl: Option[X509Crl] = None) {

  import PublicationSet._

  def applyEvent(event: SignerUpdatedPublicationSet) = {
    val withdrawnHashes = event.withdraws.map(_.hash)
    val remainingItems = items.filterKeys(k => !withdrawnHashes.contains(k))
    val newOrUpdatedItems = convertToHashMap(event.publishes.map(_.repositoryObject))
    
    copy(number = event.number, items = remainingItems ++ newOrUpdatedItems, mft = Some(event.newMft), crl = Some(event.newCrl))
  }

  private def convertToHashMap(repositoryObjects: List[CertificateRepositoryObject]) = {
    repositoryObjects.map { ro => (ReferenceHash.fromBytes(ro.getEncoded) -> ro) }.toMap
  }

  def publish(aggregateId: UUID, resourceClassName: String, baseUri: URI, mft: ManifestCms, crl: X509Crl, products: List[CertificateRepositoryObject] = List.empty) = {

    def deriveUri(repositoryObject: CertificateRepositoryObject) = baseUri.resolve(RpkiObjectNameSupport.deriveName(repositoryObject))

    // all current products
    val newProducts = convertToHashMap(products :+ mft :+ crl)

    def isUnchanged(entry: (ReferenceHash, CertificateRepositoryObject)) = {
      items.get(entry._1) match {
        case None => false
        case Some(old) => old.equals(entry._2)
      }
    }

    // publish all NEW products (i.e. minus unchanged)
    val publishes = newProducts.filterNot(isUnchanged(_)).map { e =>
      val hash = e._1
      val newObject = e._2
      val uri = deriveUri(newObject)
      Publish.forRepositoryObject(uri, newObject, items.get(hash)) // Will include old object hash only if item exists for hash
    }.toList

    val withdrawals = items.filterNot(e => newProducts.isDefinedAt(e._1)).values.map { oldObject =>
      Withdraw.forRepositoryObject(deriveUri(oldObject), oldObject)
    }.toList

    SignerUpdatedPublicationSet(aggregateId, resourceClassName, number.add(BigInteger.ONE), mft, crl, publishes, withdrawals)
  }

}