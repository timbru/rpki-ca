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

case class PublicationSet(number: BigInteger, items: Map[URI, CertificateRepositoryObject] = Map.empty, mft: Option[ManifestCms] = None, crl: Option[X509Crl] = None) {

  import PublicationSet._

  def applyEvent(event: SignerUpdatedPublicationSet) = {
    val withdrawnHashes = event.withdraws.map(_.hash)
    val remainingItems = items.filterKeys(k => !withdrawnHashes.contains(k))
    val newOrUpdatedItems = event.publishes.map(p => p.uri -> p.repositoryObject)

    copy(number = event.number, items = remainingItems ++ newOrUpdatedItems, mft = Some(event.newMft), crl = Some(event.newCrl))
  }

  def publish(resourceClassName: String, baseUri: URI, mft: ManifestCms, crl: X509Crl, products: List[CertificateRepositoryObject] = List.empty) = {

    def deriveUri(repositoryObject: CertificateRepositoryObject) = baseUri.resolve(RpkiObjectNameSupport.deriveName(repositoryObject))

    // all current products
    val newProducts = products :+ mft :+ crl
    val existingProducts = items.values.toList

    def isUnchanged(repoObject: CertificateRepositoryObject) = existingProducts.contains(repoObject)

    // publish all NEW products (i.e. minus unchanged)
    val publishes = newProducts.filterNot(isUnchanged(_)).map { p =>
      val hash = ReferenceHash.fromBytes(p.getEncoded)
      val uri = deriveUri(p)
      Publish.forRepositoryObject(uri, p, items.get(uri)) // Will include old object hash only if item exists for hash
    }.toList

    val remainingUris = newProducts.map(deriveUri(_))
    val withdrawals = items.filterNot(e => remainingUris.contains(e._1)).values.map { oldObject =>
      Withdraw.forRepositoryObject(deriveUri(oldObject), oldObject)
    }.toList

    SignerUpdatedPublicationSet(resourceClassName, number.add(BigInteger.ONE), mft, crl, publishes, withdrawals)
  }

}