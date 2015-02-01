/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
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