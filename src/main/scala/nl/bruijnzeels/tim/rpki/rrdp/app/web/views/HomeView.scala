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
package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.Text
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.rrdp.app.Main
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchor
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServer
import scala.xml.XML
import org.apache.commons.lang.StringEscapeUtils

class HomeView(ta: TrustAnchor, publicationServer: PublicationServer) extends View {

  def tab = Tabs.HomeTab
  def title = Text("RRDP Proof of concept server")
  def body = {
    <pre class="alert-message block-message alert monospace">{ ta.tal }</pre>
    <div class="alert-message block-message info">
      <div class="row">
        <div class="span12 center">Publication Server Details</div>
      </div>
      <div class="row">
        <div class="span6">Session Id</div>
        <div class="span6">{ publicationServer.sessionId } </div>
      </div>
      <div class="row">
        <div class="span6">Last serial</div>
        <div class="span6">{ publicationServer.serial } </div>
      </div>
      <div class="row">
        <div class="span6">Notification File</div>
        <div class="span6"><a href={PocDsl.RrdpNotifyUrl.toString}>{ PocDsl.RrdpNotifyUrl.toString }</a></div>
      </div>
    </div>

  }

}