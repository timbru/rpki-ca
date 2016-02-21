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

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload
import nl.bruijnzeels.tim.rpki.ca.common.domain.{Revocation, SigningMaterial}
import nl.bruijnzeels.tim.rpki.publication.messages.{Publish, Withdraw}

sealed trait SignerEvent extends ResourceClassEvent

case class SignerCreated(resourceClassName: String) extends SignerEvent
case class SignerSigningMaterialCreated(resourceClassName: String, signingMaterial: SigningMaterial) extends SignerEvent
case class SignerCreatedPendingCertificateRequest(resourceClassName: String, request: CertificateIssuanceRequestPayload) extends SignerEvent
case class SignerReceivedCertificate(resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerSignedCertificate(resourceClassName: String, certificate: X509ResourceCertificate) extends SignerEvent
case class SignerAddedRevocation(resourceClassName: String, revocation: Revocation) extends SignerEvent

sealed trait PublicationSetEvent extends SignerEvent

case class SignerUpdatedPublicationSet(
    resourceClassName: String,
    number: BigInteger,
    newMft: ManifestCms,
    newCrl: X509Crl,
    publishes: List[Publish] = List.empty,
    withdraws: List[Withdraw] = List.empty) extends PublicationSetEvent