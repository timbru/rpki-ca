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
package nl.bruijnzeels.tim.rpki.ca.provisioning

import java.net.URI
import java.util.UUID

import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload
import nl.bruijnzeels.tim.rpki.ca.common.domain.SigningSupport


/**
 * Handles identities, communication messages, and validation between
 * this CA and its children
 */
case class ProvisioningCommunicator(
    me: MyIdentity,
    parent: Option[ParentIdentity] = None,
    parentExchanges: List[ProvisioningParentExchange] = List.empty,
    children: Map[UUID, ChildIdentity] = Map.empty,
    childExchanges: List[ProvisioningChildExchange] = List.empty) {

  val UpDownUri = URI.create("http://invalid.com/") // TODO.. won't use http for now..

  def applyEvent(event: ProvisioningCommunicatorEvent) = event match {
    case created: ProvisioningCommunicatorCreated => ProvisioningCommunicator(created.myIdentity)
    
    case childAdded: ProvisioningCommunicatorAddedChild => copy(children = children + (childAdded.childIdentity.childId -> childAdded.childIdentity))
    case childExchangePerformed: ProvisioningCommunicatorPerformedChildExchange => copy(childExchanges = childExchanges :+ childExchangePerformed.exchange)
    
    case parentAdded: ProvisioningCommunicatorAddedParent => copy(parent = Some(parentAdded.parentIdentity))
    case parentExchangePerformed: ProvisioningCommunicatorPerformedParentExchange => copy(parentExchanges = parentExchanges :+ parentExchangePerformed.exchange)
  }

  private def validateChildDoesNotExist(childId: UUID) = if (children.isDefinedAt(childId)) { throw new IllegalArgumentException(s"Child with id $childId} should not exist") }
  private def getChild(childId: UUID) = children.get(childId).get

  def addChild(childId: UUID, childXml: String) = {
    validateChildDoesNotExist(childId)
    val childCert = new ChildIdentitySerializer().deserialize(childXml).getIdentityCertificate()
    val childIdentity = ChildIdentity(childId, childCert)
    ProvisioningCommunicatorAddedChild(childIdentity)
  }
  
  def addParent(parentXml: String) = ProvisioningCommunicatorAddedParent(ParentIdentity.fromXml(parentXml))

  def validateChildRequest(childId: UUID, cmsObject: ProvisioningCmsObject) = children.get(childId) match {
    case None => ProvisioningMessageValidationFailure("Unknown child")
    case Some(child) => child.validateMessage(cmsObject)
  }
  
  def validateParentResponse(cmsObject: ProvisioningCmsObject) = parent.get.validateMessage(cmsObject)

  def signRequest(payload: AbstractProvisioningPayload) = {
    SigningSupport.createProvisioningCms(
      sender = parent.get.myHandle,
      recipient = parent.get.parentHandle,
      signingCertificate = me.identityCertificate,
      signingKeyPair = me.keyPair,
      payload = payload)
  }
  
  def signResponse(childId: UUID, payload: AbstractProvisioningPayload) = { 
    SigningSupport.createProvisioningCms(
      sender = me.id.toString(),
      recipient = childId.toString,
      signingCertificate = me.identityCertificate,
      signingKeyPair = me.keyPair,
      payload = payload)
  }

  def getExchangesForChild(childId: UUID) = childExchanges.filter(_.childId == childId)

  def getParentXmlForChild(childId: UUID) = {
    import net.ripe.rpki.commons.provisioning.identity._

    children.get(childId).map { child =>
      val childCert = child.identityCertificate
      val parentCert = me.identityCertificate
      val parentIdentity = new ParentIdentity(UpDownUri, me.id.toString, childId.toString, parentCert, childCert)
      new ParentIdentitySerializer().serialize(parentIdentity)
    }
  }

}

object ProvisioningCommunicator {
  def create(aggregateId: UUID) = ProvisioningCommunicatorCreated(MyIdentity.create(aggregateId))
}