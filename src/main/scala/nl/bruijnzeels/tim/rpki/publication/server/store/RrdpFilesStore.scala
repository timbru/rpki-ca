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
package nl.bruijnzeels.tim.rpki.publication.server.store

import java.io.File
import java.sql.ResultSet
import javax.sql.DataSource

import com.google.common.io.BaseEncoding
import com.googlecode.flyway.core.Flyway
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.{EventListener, StoredEvent}
import nl.bruijnzeels.tim.rpki.publication.messages.{DeltaProtocolMessage, ReferenceHash}
import nl.bruijnzeels.tim.rpki.publication.server.{PublicationServerReceivedDelta, PublicationServerReceivedSnapshot}
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import org.apache.commons.dbcp.BasicDataSource
import org.joda.time.DateTime
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.{JdbcTemplate, RowMapper}

class RrdpFilesStore(dataSource: BasicDataSource) extends EventListener {

  val template: JdbcTemplate = new JdbcTemplate(dataSource)
  val base64 = BaseEncoding.base64()

  override def handle(storedEvents: List[StoredEvent]) = {

    storedEvents.map(_.event).foreach(event => event match {
      case deltaReceived: PublicationServerReceivedDelta => storeProtocolFile(deltaReceived.delta)
      case snapshotReceived: PublicationServerReceivedSnapshot => storeProtocolFile(snapshotReceived.snapshot)
      case _ => // These are not the droids we're looking for
    })

  }

  private def storeProtocolFile(file: DeltaProtocolMessage) = put(file.toXml.toString.getBytes("UTF-8"))

  def put(bytes: Array[Byte]): ReferenceHash = {
    val hash = ReferenceHash.fromBytes(bytes)

    template.update("insert into rrdp_files (hash, bytes, storage_time) values (?, ?, ?)",
      hash.toString, base64.encode(bytes), new java.sql.Timestamp(DateTime.now().getMillis()))

    hash
  }

  def retrieve(hash: ReferenceHash) = {
    try {
      Some(template.queryForObject("select bytes from rrdp_files where hash = ?", Array[Object](hash.toString), new RowMapper[Array[Byte]]() {
        override def mapRow(rs: ResultSet, rowNum: Int) = base64.decode(rs.getString("bytes"))
      }))
    } catch {
      case e: EmptyResultDataAccessException => None
    }
  }

}

object RrdpFilesDataSources {

  /**
   * Store data on disk.
   */
  def DurableDataSource = {
    val result = new BasicDataSource
    result.setUrl("jdbc:h2:" + ApplicationOptions.rrdpFilesStore + File.separator + "rrdp-files-store")
    result.setDriverClassName("org.h2.Driver")
    result.setDefaultAutoCommit(true)
    migrate(result)
    result
  }

  /**
   * For unit testing
   */
  def InMemoryDataSource = {
    val result = new BasicDataSource
    result.setUrl("jdbc:h2:mem:rrdp-files-store")
    result.setDriverClassName("org.h2.Driver")
    result.setDefaultAutoCommit(true)
    migrate(result)
    result
  }

  private def migrate(dataSource: DataSource) {
    val flyway = new Flyway
    flyway.setDataSource(dataSource)
    flyway.setLocations("/db/rrdp_files/")
    flyway.migrate
  }
}