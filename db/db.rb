# Copyright [2019] [University of Aizu]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'bundler/setup'

require 'fileutils'
require 'json'
require 'sqlite3'
require 'open-uri'
require 'yaml'
require 'zip'

class DB
  def initialize
    @config = YAML.load_file('./config.yml')
    FileUtils.mkdir_p("./#{@config['db_path']}") unless Dir.exist?("./#{@config['db_path']}")

    @years = @config['nvd']['year']['current'].to_i - @config['nvd']['year']['oldest'].to_i + 1
    @base_year = @config['nvd']['year']['oldest'].to_i
  end

  def create_cve
    db = SQLite3::Database.new("./#{@config['db_path']}/cve.sqlite3")
    create_table_cve(db)

    insert_proc = proc do |cve_hash|
      sql = <<-SQL
      INSERT INTO cve (cve, nvd_id, description) values (?, ?, ?)
      SQL

      cve_hash['CVE_Items'].each_with_index do |cve_item, nvd_id|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        cve_item['cve']['description']['description_data'].each { |description| db.execute(sql, cve, nvd_id, description['value']) }
      end
    end
    shared_insert_nvd(db, &insert_proc)

    db.close
  end

  def create_cwe
    db = SQLite3::Database.new("./#{@config['db_path']}/cwe.sqlite3")
    create_table_cwe(db)

    insert_proc = proc do |cve_hash|
      sql = <<-SQL
      INSERT INTO cwe (cve, cwe) values (?, ?)
      SQL

      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        cve_item['cve']['problemtype']['problemtype_data'].each do |problemtype_data|
          problemtype_data['description'].each { |cwe_description| db.execute(sql, cve, cwe_description['value']) }
        end
      end
    end
    shared_insert_nvd(db, &insert_proc)

    db.close
  end

  def create_cpe
    db = SQLite3::Database.new("./#{@config['db_path']}/cpe.sqlite3")
    create_table_cpe(db)

    insert_proc = proc do |cve_hash|
      sql = <<-SQL
      INSERT INTO cpe (cve, cpe) values (?, ?)
      SQL

      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        cve_item['configurations']['nodes'].each do |node|
          node['cpe_match'].each { |cpe| db.execute(sql, cve, cpe['cpe23Uri']) } if node.key?('cpe_match')
        end
      end
    end
    shared_insert_nvd(db, &insert_proc)

    db.close
  end

  def create_cvss_v2
    db = SQLite3::Database.new("./#{@config['db_path']}/cvss_v2.sqlite3")
    create_table_cvss_v2(db)

    insert_proc = proc do |cve_hash|
      sql = <<-SQL
      INSERT INTO cvss_v2 (
      cve, vector_string, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, base_score
      ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
      SQL

      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        next unless cve_item['impact'].key?('baseMetricV2')

        cvss = cve_item['impact']['baseMetricV2']['cvssV2']
        db.execute(
          sql, cve, cvss['vectorString'], cvss['accessVector'], cvss['accessComplexity'], cvss['authentication'],
          cvss['confidentialityImpact'], cvss['integrityImpact'], cvss['availabilityImpact'], cvss['baseScore']
        )
      end
    end
    shared_insert_nvd(db, &insert_proc)

    db.close
  end

  def create_cvss_v3
    db = SQLite3::Database.new("./#{@config['db_path']}/cvss_v3.sqlite3")
    create_table_cvss_v3(db)

    insert_proc = proc do |cve_hash|
      sql = <<-SQL
      INSERT INTO cvss_v3 (
      cve, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact,
      base_score, base_severity) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      SQL

      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        next unless cve_item['impact'].key?('baseMetricV3')

        cvss = cve_item['impact']['baseMetricV3']['cvssV3']
        db.execute(
          sql, cve, cvss['vectorString'], cvss['attackVector'], cvss['attackComplexity'], cvss['privilegesRequired'], cvss['userInteraction'], cvss['scope'],
          cvss['confidentialityImpact'], cvss['integrityImpact'], cvss['availabilityImpact'], cvss['baseScore'], cvss['baseSeverity']
        )
      end
    end
    shared_insert_nvd(db, &insert_proc)

    db.close
  end

  def create_vultest
    db = SQLite3::Database.new("./#{@config['db_path']}/vultest.sqlite3")
    create_table_vultest(db)
    insert_vultest(db)
    db.close
  end

  def download_nvd
    nvd_path = "./#{@config['src_path']}/nvd"
    src_path = "./#{nvd_path}/src"
    FileUtils.mkdir_p(nvd_path) unless Dir.exist?(nvd_path)
    FileUtils.mkdir_p(src_path) unless Dir.exist?(src_path)

    @years.times do |i|
      json_file = "nvdcve-1.1-#{@base_year + i}.json"
      zip_file = "nvdcve-1.1-#{@base_year + i}.json.zip"
      url = @config['nvd']['url']

      Dir.chdir(src_path) do
        URI.parse("#{url}/#{zip_file}").open do |f|
          File.open(zip_file, 'wb') { |sf| sf.write(f.read) }
        end
      end

      unzip("#{src_path}/#{zip_file}", "#{nvd_path}/#{json_file}")
    end
  end

  private

  def create_table_cve(db)
    sql = <<-SQL
    CREATE TABLE cve (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve VARCHAR(200) NOT NULL,
    nvd_id INTEGER NOT NULL,
    description VARCHAR
    )
    SQL
    db.execute(sql)
  end

  def create_table_cwe(db)
    sql = <<-SQL
    CREATE TABLE cwe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve VARCHAR(200) NOT NULL,
    cwe INTEGER NOT NULL
    )
    SQL
    db.execute(sql)
  end

  def create_table_cpe(db)
    sql = <<-SQL
    CREATE TABLE cpe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve VARCHAR(200) NOT NULL,
    cpe VARCHAR NOT NULL
    )
    SQL
    db.execute(sql)
  end

  def create_table_cvss_v2(db)
    sql = <<-SQL
    CREATE TABLE cvss_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve VARCHAR(200) NOT NULL,
    vector_string VARCHAR,
    access_vector VARCHAR,
    access_complexity VARCHAR,
    authentication VARCHAR,
    confidentiality_impact VARCHAR,
    cofidentiality_impact VARCHAR,
    integrity_impact VARCHAR,
    availability_impact VARCHAR,
    base_score INTEGER
    )
    SQL
    db.execute(sql)
  end

  def create_table_cvss_v3(db)
    sql = <<-SQL
    CREATE TABLE cvss_v3 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve VARCHAR(200) NOT NULL,
    vector_string VARCHAR,
    attack_vector VARCHAR,
    attack_complexity VARCHAR,
    privileges_required VARCHAR,
    user_interaction VARCHAR,
    scope VARCHAR,
    confidentiality_impact VARCHAR,
    integrity_impact VARCHAR,
    availability_impact VARCHAR,
    base_score INTEGER,
    base_severity VARCHAR
    )
    SQL
    db.execute(sql)
  end

  def create_table_vultest(db)
    sql = <<-SQL
    CREATE TABLE configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve VARCHAR(200) NOT NULL,
      name VARCHAR(200) NOT NULL,
      config_path VARCHAR(200) NOT NULL,
      module_path VARCHAR(200) NOT NULL
    );
    SQL

    db.execute(sql)
  end

  def shared_insert_nvd(db, &block)
    @years.times do |i|
      File.open("./#{@config['src_path']}/nvd/nvdcve-1.1-#{@base_year + i}.json") do |file|
        cve_hash = JSON.parse(file.read)
        db.transaction { block.call(cve_hash) }
      end
    end
  end

  def insert_vultest(db)
    sql = 'INSERT INTO configs (cve, name, config_path, module_path) values (? ,?, ?, ?)'
    data = YAML.load_file("./#{@config['src_path']}/vultest/vultest_data.yml")
    data.each do |vuldata|
      db.execute(
        sql,
        vuldata['vuln']['cve'], vuldata['vuln']['name'],
        vuldata['vuln']['data']['env_path'], vuldata['vuln']['data']['attack_path']
      )
    end
  end

  def unzip(zip_file_path, save_file_path)
    Zip::File.open(zip_file_path) do |zip|
      zip.each do |entry|
        zip.extract(entry, save_file_path) { true }
      end
    end
  end
end
