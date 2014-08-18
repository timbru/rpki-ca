package nl.bruijnzeels.tim.rpki.rrdp.app

import com.typesafe.config.{ ConfigFactory, Config }
import java.net.URI
import java.io.File

object ApplicationOptions {

  private val config: Config = ConfigFactory.load()

  def rrdpPort: Int = config.getInt("rrdp.http.port")
  def rrdpHost: String = config.getString("rrdp.http.host")
  def rrdpProxy: Boolean = config.getBoolean("rrdp.http.proxy")
  def rsyncBaseUri: URI = URI.create(config.getString("rsync.base.uri"))

  def rrdpBaseUri = rrdpProxy match {
    case true => URI.create(s"http://${rrdpHost}/rpki-ca/")
    case false => URI.create(s"http://${rrdpHost}:${rrdpPort}/rpki-ca/")
  }

  def rrdpFilesStore =  new File(config.getString("rrdp.data.dir"))

}