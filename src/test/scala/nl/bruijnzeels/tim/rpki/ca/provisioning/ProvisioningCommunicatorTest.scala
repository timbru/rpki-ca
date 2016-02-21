/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
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

import java.util.UUID

import net.ripe.rpki.commons.provisioning.identity.ParentIdentitySerializer
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder
import org.scalatest.{FunSuite, Matchers}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ProvisioningCommunicatorTest extends FunSuite with Matchers {

  test("Should create provisioning communicator") {
    val id = UUID.randomUUID()
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(id).myIdentity)
    
    pc.me.id should equal (id)
  }
  
  test("Should create parent xml") {
    val childId = MyIdentity.create(UUID.randomUUID)
    val childXml = childId.toChildXml
    
    val pc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val parentXml = pc.applyEvent(pc.addChild(childId.id, childXml)).getParentXmlForChild(childId.id)
    
    val parentId = new ParentIdentitySerializer().deserialize(parentXml.get)
    
    parentId.getChildHandle() should equal(childId.id.toString)
    parentId.getChildIdCertificate() should equal(childId.identityCertificate)

    parentId.getParentHandle() should equal(pc.me.id.toString)
    parentId.getParentIdCertificate() should equal(pc.me.identityCertificate)
  }
  
  test("Should add parent, and sign requests to parent with proper sender and recipient..") {
    val childPc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val childXml = childPc.me.toChildXml
    
    val parentPc = ProvisioningCommunicator(ProvisioningCommunicator.create(UUID.randomUUID()).myIdentity)
    val parentXml = parentPc.applyEvent(parentPc.addChild(childPc.me.id, childXml)).getParentXmlForChild(childPc.me.id).get
    
    val childWithParent = childPc.applyEvent(childPc.addParent(parentXml))
    
    childWithParent.parent should equal(Some(ParentIdentity.fromXml(parentXml)))
    
    val requestCms = childWithParent.signRequest(new ResourceClassListQueryPayloadBuilder().build())
    val requestPayload = requestCms.getPayload()
    
    val parentId = new ParentIdentitySerializer().deserialize(parentXml)
    
    requestPayload.getRecipient() should equal(parentId.getParentHandle())
    requestPayload.getSender() should equal(parentId.getChildHandle())
  }
  
}