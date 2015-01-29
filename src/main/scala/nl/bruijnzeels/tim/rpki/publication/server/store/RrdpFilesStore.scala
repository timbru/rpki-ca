package nl.bruijnzeels.tim.rpki.publication.server.store

import java.io.File
import javax.sql.DataSource
import com.googlecode.flyway.core.Flyway
import org.apache.commons.dbcp.BasicDataSource
import scala.xml.Elem
import nl.bruijnzeels.tim.rpki.publication.messages.ReferenceHash
import org.springframework.jdbc.core.JdbcTemplate
import org.joda.time.DateTime
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.RowMapper
import java.sql.ResultSet
import com.google.common.io.BaseEncoding
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventListener
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerReceivedDelta
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerReceivedSnapshot
import nl.bruijnzeels.tim.rpki.publication.messages.DeltaProtocolMessage
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.StoredEvent

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